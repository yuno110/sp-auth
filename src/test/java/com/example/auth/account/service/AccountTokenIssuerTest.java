package com.example.auth.account.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.global.config.MailExecutorConfig;
import com.example.auth.mail.MailDispatcher;
import com.example.auth.mail.MailSettings;
import com.example.auth.mail.OutgoingMail;
import com.example.auth.support.InMemoryMailer;
import com.example.auth.support.MutableClock;
import com.example.auth.support.TestRsaKeys;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.AdditionalAnswers;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 링크 토큰 발급 작업 (sp-docs/plan/phase2-auth-member.md AU-15 의 검증 표, sp-docs/requirements/member.md §11).
 *
 * <p>대부분의 테스트는 발급 작업을 직접 만든다. DB·트랜잭션 관리자·리포지토리는 애플리케이션의 것이고, 실행기는
 * 넘겨받은 작업을 모으기만 하는 것({@link #handedOver})이다 — 발급 작업과 그 작업이 커밋 뒤에 넘긴 발송을 이 스레드에서
 * 차례로 돌려({@link #넘겨받은_작업을_돌린다()}) 메일이 없다는 단언도 기다림 없이 확정한다. 발송기는 받은 메일을
 * 모은다({@link #delivered}). 시계는 {@link MutableClock} 이고 발송 상한도 그 시계로 만든다.
 *
 * <p>애플리케이션의 빈이 발송 실행기에서 도는지는 {@link #빈은_작업을_발송_실행기에서_돌린다()} 가 본다.
 *
 * <p>테스트끼리 같은 DB 를 쓰므로 계정의 이메일은 테스트마다 다르고, 테스트가 끝나면 만든 행을 지운다.
 */
@SpringBootTest
@ActiveProfiles("test")
class AccountTokenIssuerTest {

	/** 앱 설정과 다른 값이다 — 링크의 기준 주소가 이 설정에서 오는지 본다. */
	private static final String FRONTEND_BASE_URL = "https://front.example.test";

	private static final LocalDateTime NOW = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	/** 이 클래스가 만드는 계정의 이메일 접두어(대소문자 무시). 정리가 이것으로 자기 행만 지운다. */
	private static final String EMAIL_PREFIX = "au15-";

	// 해시가 아니다. 커밋되는 파일에 BCrypt 모양 문자열을 두지 않는다
	// (sp-docs/requirements/member.md §10.2). 발급 작업은 비밀번호를 읽지 않는다
	private static final String RAW_ENCODED_PASSWORD = "test-not-a-hash-encoded-password";

	private static final Pattern VERIFY_LINK =
			Pattern.compile(Pattern.quote(FRONTEND_BASE_URL + "/verify-email#token=") + "([^\\s]+)");

	private static final Pattern RESET_LINK =
			Pattern.compile(Pattern.quote(FRONTEND_BASE_URL + "/reset-password#token=") + "([^\\s]+)");

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private AccountTokenRepository accountTokenRepository;

	@Autowired
	private PlatformTransactionManager transactionManager;

	/** 커밋된 행을 영속성 컨텍스트를 거치지 않고 읽는다. */
	@Autowired
	private JdbcTemplate jdbcTemplate;

	/** 열린 트랜잭션과 다른 연결을 얻는다 — 커밋된 행만 보인다. */
	@Autowired
	private DataSource dataSource;

	private final MutableClock clock = new MutableClock();

	private final List<Runnable> handedOver = new ArrayList<>();

	private final List<OutgoingMail> delivered = new ArrayList<>();

	private final AccountTokenSendLimit sendLimit = new AccountTokenSendLimit(this.clock);

	private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

	private AccountTokenIssuer issuer;

	@BeforeEach
	void setUp() {
		this.clock.set(NOW);
		this.issuer = 발급_작업(this.accountRepository, this.accountTokenRepository);
		this.appender.start();
		issuerLogger().addAppender(this.appender);
	}

	/**
	 * 만든 행을 지운다. H2 는 테스트 클래스 사이에 공유되므로({@code DB_CLOSE_DELAY=-1}) 토큰 행을 남기면 다른 클래스의
	 * 계정 정리가 {@code fk_account_token_account} 에 걸린다(2026-11-13 측정) — 토큰을 먼저 지우고, 계정은 이 클래스가
	 * 만든 것만 지운다.
	 */
	@AfterEach
	void tearDown() {
		issuerLogger().detachAppender(this.appender);
		this.appender.stop();
		this.accountTokenRepository.deleteAll();
		this.accountRepository.deleteAll(this.accountRepository.findAll().stream()
				.filter(account -> account.getEmail().toLowerCase(Locale.ROOT).startsWith(EMAIL_PREFIX))
				.toList());
	}

	// --- 요청 스레드 ---

	@Test
	@DisplayName("요청은 작업을 실행기에 넘기기만 한다 — 부른 스레드는 DB 일을 하지 않는다")
	void 요청은_작업을_넘기기만_한다() {
		AccountRepository accounts = mock(AccountRepository.class);
		AccountTokenRepository tokens = mock(AccountTokenRepository.class);
		AccountTokenIssuer issuer = 발급_작업(accounts, tokens);

		issuer.request(TokenPurpose.PASSWORD_RESET, "au15-handover@example.com");

		assertThat(this.handedOver).hasSize(1);
		verifyNoInteractions(accounts, tokens);

		넘겨받은_작업을_돌린다();
		verify(accounts).findByEmail("au15-handover@example.com");
	}

	// --- 재발송 (sp-docs/requirements/member.md §11.2) ---

	@Test
	@DisplayName("재발송 — 활성·미인증이면 토큰 한 행과 메일 한 통. 링크의 토큰을 해시하면 저장값이다")
	void 재발송_활성_미인증() {
		Account account = 계정("au15-resend-active@example.com");

		this.issuer.request(TokenPurpose.EMAIL_VERIFICATION, account.getEmail());
		넘겨받은_작업을_돌린다();

		assertThat(this.delivered).hasSize(1);
		OutgoingMail mail = this.delivered.get(0);
		assertThat(mail.to()).isEqualTo(account.getEmail());
		assertThat(mail.accountId()).isEqualTo(account.getId());
		assertThat(mail.purpose()).isEqualTo(TokenPurpose.EMAIL_VERIFICATION.name());
		assertThat(mail.text()).contains("가입하지 않았다면 이 메일을 무시하세요");

		String token = 링크의_토큰(mail, VERIFY_LINK);
		assertThat(token).as("32바이트의 base64url(패딩 없음)").hasSize(43).matches("[A-Za-z0-9_-]+");
		assertThat(Base64.getUrlDecoder().decode(token)).hasSize(32);

		List<Map<String, Object>> rows = 토큰_행(account.getId());
		assertThat(rows).hasSize(1);
		assertThat(rows.get(0))
				.containsEntry("purpose", TokenPurpose.EMAIL_VERIFICATION.name())
				.containsEntry("token_hash", sha256Hex(token));
		assertThat(시각(account.getId(), "created_at")).isEqualTo(NOW);
		assertThat(시각(account.getId(), "expires_at")).as("인증 24시간").isEqualTo(NOW.plusHours(24));
	}

	@Test
	@DisplayName("재발송 — 계정이 없거나 탈퇴했거나 이미 인증됐으면 행도 메일도 없다")
	void 재발송_보내지_않는_계정() {
		Account withdrawn = 탈퇴한_계정("au15-resend-withdrawn@example.com");
		Account verified = 인증한_계정("au15-resend-verified@example.com");
		int rowsBefore = 전체_토큰_행_수();

		this.issuer.request(TokenPurpose.EMAIL_VERIFICATION, "au15-resend-none@example.com");
		this.issuer.request(TokenPurpose.EMAIL_VERIFICATION, withdrawn.getEmail());
		this.issuer.request(TokenPurpose.EMAIL_VERIFICATION, verified.getEmail());
		넘겨받은_작업을_돌린다();

		assertThat(this.delivered).isEmpty();
		assertThat(전체_토큰_행_수()).isEqualTo(rowsBefore);
	}

	// --- 재설정 요청 (sp-docs/requirements/member.md §11.3) ---

	@Test
	@DisplayName("재설정 — 활성이면 인증 여부와 상관없이 메일이 간다. 수명은 30분이다")
	void 재설정_활성() {
		Account verified = 인증한_계정("au15-reset-verified@example.com");
		Account unverified = 계정("au15-reset-unverified@example.com");

		this.issuer.request(TokenPurpose.PASSWORD_RESET, verified.getEmail());
		this.issuer.request(TokenPurpose.PASSWORD_RESET, unverified.getEmail());
		넘겨받은_작업을_돌린다();

		assertThat(this.delivered).extracting(OutgoingMail::to)
				.containsExactly(verified.getEmail(), unverified.getEmail());
		for (OutgoingMail mail : this.delivered) {
			assertThat(mail.purpose()).isEqualTo(TokenPurpose.PASSWORD_RESET.name());
			List<Map<String, Object>> rows = 토큰_행(mail.accountId());
			assertThat(rows).hasSize(1);
			assertThat(rows.get(0))
					.containsEntry("purpose", TokenPurpose.PASSWORD_RESET.name())
					.containsEntry("token_hash", sha256Hex(링크의_토큰(mail, RESET_LINK)));
			assertThat(시각(mail.accountId(), "expires_at")).as("재설정 30분").isEqualTo(NOW.plusMinutes(30));
		}
	}

	@Test
	@DisplayName("재설정 — 계정이 없거나 탈퇴했으면 행도 메일도 없다")
	void 재설정_보내지_않는_계정() {
		Account withdrawn = 탈퇴한_계정("au15-reset-withdrawn@example.com");
		int rowsBefore = 전체_토큰_행_수();

		this.issuer.request(TokenPurpose.PASSWORD_RESET, "au15-reset-none@example.com");
		this.issuer.request(TokenPurpose.PASSWORD_RESET, withdrawn.getEmail());
		넘겨받은_작업을_돌린다();

		assertThat(this.delivered).isEmpty();
		assertThat(전체_토큰_행_수()).isEqualTo(rowsBefore);
	}

	/**
	 * 계정 조회는 콜레이션으로 비교해 다른 표기로도 같은 계정을 찾는다 (sp-docs/requirements/member.md §11.3).
	 * H2 는 대소문자를 구분해 비교하므로 그 조회를 대역으로 만든다 — 대역은 요청의 표기로 저장된 계정을 돌려준다.
	 */
	@Test
	@DisplayName("요청의 표기와 저장된 주소가 달라도 받는 주소는 저장된 주소다")
	void 받는_주소는_저장된_주소다() {
		Account stored = 계정("AU15-Case@Example.com");
		AccountRepository collationLike = mock(AccountRepository.class);
		given(collationLike.findByEmail("au15-case@example.com")).willReturn(Optional.of(stored));

		발급_작업(collationLike, this.accountTokenRepository).request(TokenPurpose.PASSWORD_RESET, "au15-case@example.com");
		넘겨받은_작업을_돌린다();

		assertThat(this.delivered).extracting(OutgoingMail::to).containsExactly("AU15-Case@Example.com");
	}

	// --- 앞 토큰 (sp-docs/requirements/member.md §11.1) ---

	@Test
	@DisplayName("같은 계정·목적의 둘째 발급은 앞 토큰을 지운다 — 다른 목적의 토큰은 남는다")
	void 둘째_발급은_앞_토큰을_지운다() {
		Account account = 계정("au15-second@example.com");

		String firstVerification = 발급하고_토큰을_꺼낸다(TokenPurpose.EMAIL_VERIFICATION, account, VERIFY_LINK);
		String reset = 발급하고_토큰을_꺼낸다(TokenPurpose.PASSWORD_RESET, account, RESET_LINK);
		String secondVerification = 발급하고_토큰을_꺼낸다(TokenPurpose.EMAIL_VERIFICATION, account, VERIFY_LINK);

		assertThat(토큰_행(account.getId())).extracting(row -> row.get("token_hash"))
				.containsExactlyInAnyOrder(sha256Hex(secondVerification), sha256Hex(reset))
				.doesNotContain(sha256Hex(firstVerification));
	}

	// --- 발송 상한 (sp-docs/requirements/member.md §11.5) ---

	@Test
	@DisplayName("발송 상한을 넘으면 새 행도 메일도 없고 WARN 이다 — 마지막 링크가 살고, 목적마다 따로 세고, 한 시간 뒤에 다시 보낸다")
	void 발송_상한을_넘으면_보내지_않는다() {
		Account account = 계정("au15-limit@example.com");
		String last = null;
		for (int i = 0; i < 3; i++) {
			last = 발급하고_토큰을_꺼낸다(TokenPurpose.PASSWORD_RESET, account, RESET_LINK);
		}

		this.issuer.request(TokenPurpose.PASSWORD_RESET, account.getEmail());
		넘겨받은_작업을_돌린다();

		assertThat(this.delivered).as("넷째는 보내지 않는다").hasSize(3);
		assertThat(토큰_행(account.getId())).extracting(row -> row.get("token_hash"))
				.as("마지막으로 보낸 링크의 행만 있다").containsExactly(sha256Hex(last));
		assertThat(this.accountTokenRepository.findByTokenHash(sha256Hex(last))).as("그 링크의 토큰으로 읽힌다")
				.isPresent();
		ILoggingEvent warning = 경고_한_줄();
		assertThat(warning.getFormattedMessage())
				.contains("send limit", "accountId=" + account.getId(), "purpose=" + TokenPurpose.PASSWORD_RESET)
				.doesNotContain(account.getEmail(), last);

		assertThat(발급하고_토큰을_꺼낸다(TokenPurpose.EMAIL_VERIFICATION, account, VERIFY_LINK))
				.as("다른 목적은 따로 센다").isNotNull();

		this.clock.set(NOW.plusHours(1));
		assertThat(발급하고_토큰을_꺼낸다(TokenPurpose.PASSWORD_RESET, account, RESET_LINK))
				.as("한 시간 뒤에는 다시 보낸다").isNotNull();
	}

	// --- 되돌림 ---

	/**
	 * 모든 단계가 돈 뒤 커밋 자리에서 되돌린다 — 실제 관리자로 되돌리고 커밋 실패를 던진다. 커밋 뒤 발송을 건 다음이므로
	 * 메일이 커밋을 기다리는지를 본다. 같은 트랜잭션의 앞 토큰 지우기도 되돌려지고, 잡았던 상한의 한 통도 돌아온다 — 앞서
	 * 보낸 한 통에 더해 두 통을 더 보낼 수 있고 그다음이 상한이다.
	 */
	@Test
	@DisplayName("발급 트랜잭션이 되돌려지면 메일이 없다 — 앞 토큰이 남고, 상한을 쓰지 않고, WARN 에 토큰이 없다")
	void 발급_트랜잭션이_되돌려지면_메일이_없다() {
		Account account = 계정("au15-rollback@example.com");
		String previous = 발급하고_토큰을_꺼낸다(TokenPurpose.PASSWORD_RESET, account, RESET_LINK);
		String secret = "token_hash=" + sha256Hex(previous);
		PlatformTransactionManager rollingBack = mock(PlatformTransactionManager.class,
				AdditionalAnswers.delegatesTo(this.transactionManager));
		willAnswer(invocation -> {
			this.transactionManager.rollback(invocation.getArgument(0));
			throw new TransactionSystemException("commit failed " + secret);
		}).given(rollingBack).commit(any());

		발급_작업(this.accountRepository, this.accountTokenRepository, rollingBack, this.handedOver::add)
				.request(TokenPurpose.PASSWORD_RESET, account.getEmail());
		넘겨받은_작업을_돌린다();

		verify(rollingBack).commit(any());
		assertThat(this.delivered).as("앞서 보낸 한 통뿐이다").hasSize(1);
		assertThat(토큰_행(account.getId())).extracting(row -> row.get("token_hash"))
				.as("앞 토큰 지우기도 되돌려졌다").containsExactly(sha256Hex(previous));
		ILoggingEvent warning = 경고_한_줄();
		assertThat(warning.getFormattedMessage())
				.contains("issue failed", "accountId=" + account.getId(), "purpose=" + TokenPurpose.PASSWORD_RESET,
						TransactionSystemException.class.getName())
				.doesNotContain(secret, previous, account.getEmail());
		assertThat(warning.getThrowableProxy()).as("예외를 붙이면 메시지와 스택이 함께 남는다").isNull();

		발급하고_토큰을_꺼낸다(TokenPurpose.PASSWORD_RESET, account, RESET_LINK);
		발급하고_토큰을_꺼낸다(TokenPurpose.PASSWORD_RESET, account, RESET_LINK);
		this.issuer.request(TokenPurpose.PASSWORD_RESET, account.getEmail());
		넘겨받은_작업을_돌린다();
		assertThat(this.delivered).as("되돌려진 발급은 상한에 들지 않는다 — 세 통 뒤가 상한이다").hasSize(3);
	}

	// --- 가입 (AU-16 이 잇는다) ---

	@Test
	@DisplayName("가입의 발급은 계정 INSERT 가 커밋된 뒤에 넘기고, 재발송과 같은 작업을 지난다 — 같은 상한에 든다")
	void 가입의_발급은_커밋_뒤에_넘긴다() {
		String email = "au15-signup@example.com";
		List<Integer> committedAccountsAtHandover = new ArrayList<>();
		AccountTokenIssuer issuer = 발급_작업(this.accountRepository, this.accountTokenRepository,
				this.transactionManager, task -> {
					committedAccountsAtHandover.add(다른_연결에서_센_계정_수(email));
					this.handedOver.add(task);
				});
		TransactionTemplate transaction = new TransactionTemplate(this.transactionManager);

		Account account = transaction.execute(status -> {
			Account created = this.accountRepository.save(새_계정(email));
			issuer.requestAfterCommit(TokenPurpose.EMAIL_VERIFICATION, created.getId());
			assertThat(this.handedOver).as("커밋 전에는 넘기지 않는다").isEmpty();
			return created;
		});
		assertThat(this.handedOver).as("커밋 뒤에 넘긴다").hasSize(1);
		assertThat(committedAccountsAtHandover).as("넘기는 때에 계정 INSERT 가 이미 커밋돼 있다").containsExactly(1);

		넘겨받은_작업을_돌린다();
		assertThat(this.delivered).hasSize(1);
		OutgoingMail mail = this.delivered.get(0);
		assertThat(mail.to()).isEqualTo(account.getEmail());
		assertThat(토큰_행(account.getId())).extracting(row -> row.get("token_hash"))
				.containsExactly(sha256Hex(링크의_토큰(mail, VERIFY_LINK)));

		발급하고_토큰을_꺼낸다(TokenPurpose.EMAIL_VERIFICATION, account, VERIFY_LINK);
		발급하고_토큰을_꺼낸다(TokenPurpose.EMAIL_VERIFICATION, account, VERIFY_LINK);
		this.issuer.request(TokenPurpose.EMAIL_VERIFICATION, account.getEmail());
		넘겨받은_작업을_돌린다();
		assertThat(this.delivered).as("가입의 한 통이 재발송과 같은 상한에 든다").hasSize(3);
	}

	@Test
	@DisplayName("가입이 되돌려지면 발급을 넘기지 않는다. 트랜잭션 밖에서 부르면 예외다")
	void 가입이_되돌려지면_넘기지_않는다() {
		TransactionTemplate transaction = new TransactionTemplate(this.transactionManager);

		transaction.executeWithoutResult(status -> {
			Account created = this.accountRepository.save(새_계정("au15-signup-rollback@example.com"));
			this.issuer.requestAfterCommit(TokenPurpose.EMAIL_VERIFICATION, created.getId());
			status.setRollbackOnly();
		});
		assertThat(this.handedOver).isEmpty();

		assertThatThrownBy(() -> this.issuer.requestAfterCommit(TokenPurpose.EMAIL_VERIFICATION, 1L))
				.isInstanceOf(IllegalStateException.class);
		assertThat(this.handedOver).isEmpty();
		assertThat(this.delivered).isEmpty();
	}

	// --- 애플리케이션의 배선 ---

	@Autowired
	private AccountTokenIssuer applicationIssuer;

	@Autowired
	@Qualifier(MailExecutorConfig.MAIL_EXECUTOR)
	private ThreadPoolTaskExecutor mailExecutor;

	@Autowired
	private InMemoryMailer inMemoryMailer;

	/**
	 * 발송 실행기의 스레드를 막아 둔 채 요청한다. 그 스레드가 하나라(2026-11-13 MailExecutorConfig 읽기) 발급 작업은 그
	 * 실행기의 대기열에 머문다 — 대기열에 없거나 막힌 동안 행이 생기면 다른 곳에서 돈 것이다.
	 */
	@Test
	@DisplayName("빈은 작업을 발송 실행기에서 돌린다 — 부른 스레드가 돌려준 뒤에 행과 메일이 생긴다")
	void 빈은_작업을_발송_실행기에서_돌린다() throws InterruptedException {
		Account account = 계정("au15-bean@example.com");
		this.inMemoryMailer.clear();
		CountDownLatch blocked = new CountDownLatch(1);
		CountDownLatch release = new CountDownLatch(1);
		this.mailExecutor.execute(() -> {
			blocked.countDown();
			try {
				release.await(10, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		});
		assertThat(blocked.await(5, TimeUnit.SECONDS)).isTrue();

		try {
			this.applicationIssuer.request(TokenPurpose.PASSWORD_RESET, account.getEmail());
			assertThat(this.mailExecutor.getThreadPoolExecutor().getQueue()).as("작업은 발송 실행기의 대기열에 있다")
					.hasSize(1);
			assertThat(토큰_행(account.getId())).as("부른 스레드에서 돌지 않았다").isEmpty();
		} finally {
			release.countDown();
		}

		InMemoryMailer.Sent sent = this.inMemoryMailer.next(Duration.ofSeconds(5));
		assertThat(sent.mail().to()).isEqualTo(account.getEmail());
		assertThat(sent.threadName()).startsWith(MailExecutorConfig.THREAD_NAME_PREFIX);
		assertThat(토큰_행(account.getId())).hasSize(1);
	}

	// --- 도우미 ---

	private AccountTokenIssuer 발급_작업(AccountRepository accounts, AccountTokenRepository tokens) {
		return 발급_작업(accounts, tokens, this.transactionManager, this.handedOver::add);
	}

	/** {@code jobExecutor} 는 발급 작업을 받는 실행기다. 발송은 언제나 {@link #handedOver} 로 간다. */
	private AccountTokenIssuer 발급_작업(AccountRepository accounts, AccountTokenRepository tokens,
			PlatformTransactionManager transactionManager, Executor jobExecutor) {
		MailDispatcher dispatcher = new MailDispatcher(this.delivered::add, this.handedOver::add,
				new StandardEnvironment());
		return new AccountTokenIssuer(accounts, tokens, this.sendLimit, dispatcher,
				new MailSettings("no-reply@test.invalid", FRONTEND_BASE_URL), jobExecutor,
				transactionManager, this.clock);
	}

	/** 넘겨받은 작업을 비울 때까지 차례로 돌린다. 발급 작업이 커밋 뒤에 넘긴 발송도 여기서 돈다. */
	private void 넘겨받은_작업을_돌린다() {
		while (!this.handedOver.isEmpty()) {
			this.handedOver.remove(0).run();
		}
	}

	/** 한 번 발급하고 그 메일의 링크에서 토큰을 꺼낸다. 메일이 한 통 늘어야 한다. */
	private String 발급하고_토큰을_꺼낸다(TokenPurpose purpose, Account account, Pattern link) {
		int before = this.delivered.size();
		this.issuer.request(purpose, account.getEmail());
		넘겨받은_작업을_돌린다();
		assertThat(this.delivered).hasSize(before + 1);
		return 링크의_토큰(this.delivered.get(before), link);
	}

	private static String 링크의_토큰(OutgoingMail mail, Pattern link) {
		Matcher matcher = link.matcher(mail.text());
		assertThat(matcher.find()).as("본문에 링크가 있다: " + link.pattern()).isTrue();
		return matcher.group(1);
	}

	private ILoggingEvent 경고_한_줄() {
		List<ILoggingEvent> warnings = this.appender.list.stream()
				.filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN))
				.toList();
		assertThat(warnings).hasSize(1);
		return warnings.get(0);
	}

	private Account 계정(String email) {
		return this.accountRepository.save(새_계정(email));
	}

	private Account 탈퇴한_계정(String email) {
		Account account = 새_계정(email);
		account.withdraw();
		return this.accountRepository.save(account);
	}

	private Account 인증한_계정(String email) {
		Account account = 새_계정(email);
		account.markEmailVerified(this.clock);
		return this.accountRepository.save(account);
	}

	private static Account 새_계정(String email) {
		return Account.builder().email(email).password(RAW_ENCODED_PASSWORD).build();
	}

	private List<Map<String, Object>> 토큰_행(Long accountId) {
		return this.jdbcTemplate.queryForList(
				"select purpose, token_hash from account_token where account_id = ?",
				accountId);
	}

	private int 다른_연결에서_센_계정_수(String email) {
		try (Connection connection = this.dataSource.getConnection();
				PreparedStatement statement = connection.prepareStatement("select count(*) from account where email = ?")) {
			statement.setString(1, email);
			try (ResultSet resultSet = statement.executeQuery()) {
				resultSet.next();
				return resultSet.getInt(1);
			}
		} catch (SQLException e) {
			throw new IllegalStateException(e);
		}
	}

	private int 전체_토큰_행_수() {
		return this.jdbcTemplate.queryForObject("select count(*) from account_token", Integer.class);
	}

	/** 그 계정의 토큰 행의 시각. 행이 하나일 때 쓴다. */
	private LocalDateTime 시각(Long accountId, String column) {
		return this.jdbcTemplate.queryForObject(
				"select " + column + " from account_token where account_id = ?", LocalDateTime.class, accountId);
	}

	private static String sha256Hex(String token) {
		try {
			return HexFormat.of().formatHex(
					MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	private static Logger issuerLogger() {
		return (Logger) LoggerFactory.getLogger(AccountTokenIssuer.class);
	}

}
