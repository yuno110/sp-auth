package com.example.auth.account.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.account.service.AccountTokenIssuer;
import com.example.auth.account.support.AccountTokens;
import com.example.auth.global.config.MailExecutorConfig;
import com.example.auth.global.error.GlobalExceptionHandler;
import com.example.auth.mail.MailDispatcher;
import com.example.auth.support.BlockedExecutor;
import com.example.auth.support.InMemoryMailer;
import com.example.auth.support.MailExecutorDrain;
import com.example.auth.support.TestRsaKeys;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * 메일이 나가지 못해도 받은 링크가 산다 — 앞 토큰은 발송 뒤 지우고, 확인이 나머지를 지운다 (sp-docs/plan/phase2-auth-member.md
 * AU-24 의 검증 표, sp-docs/requirements/member.md §11.1·§11.2·§11.4·§11.5, sp-docs/domain-model.md §2.4).
 *
 * <p><b>링크 1</b> 은 앞 요청의 메일에서 꺼낸 토큰이다. 인증과 재설정을 같은 모양으로 보므로 목적마다 돈다 — 인증은 재발송과
 * 인증 확인, 재설정은 재설정 요청과 재설정 확인이다.
 *
 * <p>발송의 실패는 시험용 발송기({@link InMemoryMailer#failing()})가 던지는 것으로, 버림은 실행기의 스레드를 막고 대기열을
 * 채우는 것으로 만든다. 지우기의 실패와 락 예외는 {@link AccountTokenRepository} 의 스파이가 던지는 대역이다 — H2 는
 * InnoDB 의 락을 재현하지 않으므로 교착 자체를 만들지 않는다(같은 항목의 블록인용). 대역 밖에서는 스파이가 실제 빈에
 * 위임한다. 락 예외를 리포지터리 프록시 <b>앞</b>에서 던지는 것은 일부러다 — 안(Hibernate)에서 난 락 예외는 트랜잭션을
 * rollback-only 로 표시해, 예외를 삼키는 변이도 커밋에서 500·전부 되돌림이 되므로 삼키는 것과 던지는 것을 가르지 못한다
 * (2026-11-24 AU-24 리뷰의 측정).
 *
 * <p>정리는 이 클래스가 만든 계정({@code au24-} 접두어)과 토큰 행을 지운다. H2 는 테스트 클래스 사이에 공유되므로 seed 는
 * 남긴다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountTokenLifecycleTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	private static final String NEW_PASSWORD = "NewPassw0rd!";

	/** {@code application-test.yml} 의 {@code mail.frontend-base-url}. */
	private static final String FRONTEND_BASE_URL = "http://localhost:3000";

	private static final Pattern VERIFY_LINK =
			Pattern.compile(Pattern.quote(FRONTEND_BASE_URL + "/verify-email#token=") + "(\\S+)");

	private static final Pattern RESET_LINK =
			Pattern.compile(Pattern.quote(FRONTEND_BASE_URL + "/reset-password#token=") + "(\\S+)");

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private AccountRepository accountRepository;

	/** 대역 밖에서는 실제 빈에 위임한다. 스텁은 테스트가 끝나면 지워진다. */
	@MockitoSpyBean
	private AccountTokenRepository accountTokenRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private Clock clock;

	@Autowired
	private InMemoryMailer inMemoryMailer;

	@Autowired
	@Qualifier(MailExecutorConfig.ISSUE_EXECUTOR)
	private ThreadPoolTaskExecutor issueExecutor;

	@Autowired
	@Qualifier(MailExecutorConfig.SEND_EXECUTOR)
	private ThreadPoolTaskExecutor sendExecutor;

	@AfterEach
	void 정리() {
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		this.inMemoryMailer.clear();
		this.jdbcTemplate.update("delete from account_token");
		this.jdbcTemplate.update("delete from refresh_token");
		this.jdbcTemplate.update("delete from login_attempt");
		this.jdbcTemplate.update("delete from account where email like 'au24-%'");
	}

	// --- 발송이 나가지 못하면 링크 1 이 산다 ---

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("시험용 발송기가 던진다 — 다시 요청한 동안 행이 둘이고, 링크 1 로 확인하면 204 다")
	void 발송기가_던지면_링크_1_이_산다(TokenPurpose purpose) throws Exception {
		String email = 이메일("throw", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);

		try (InMemoryMailer.Failing failing = this.inMemoryMailer.failing()) {
			요청한다(purpose, email);
			MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		}

		assertThat(행(accountId, purpose)).as("다시 요청한 동안 그 계정·목적의 행이 둘이다").hasSize(2);
		확인한다(purpose, link1).andExpect(status().isNoContent());
	}

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("발송이 성공한다 — 다시 요청한 뒤 링크 1 은 400 AU007, 새 링크는 204")
	void 발송이_성공하면_링크_1_은_죽는다(TokenPurpose purpose) throws Exception {
		String email = 이메일("success", purpose);
		미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);
		String link2 = 요청하고_토큰을_꺼낸다(purpose, email);

		링크_토큰_오류다(확인한다(purpose, link1));
		확인한다(purpose, link2).andExpect(status().isNoContent());
	}

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("발송 실행기가 그 발송 작업을 버린다 — 링크 1 로 확인하면 204 다")
	void 발송_작업이_버려지면_링크_1_이_산다(TokenPurpose purpose) throws Exception {
		String email = 이메일("send-discard", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);

		try (BlockedExecutor blocked = BlockedExecutor.block(this.sendExecutor).fill()) {
			요청한다(purpose, email);
			MailExecutorDrain.drainOnly(this.issueExecutor);
			assertThat(행(accountId, purpose)).as("발급 작업은 돌았다 — 새 행이 있다").hasSize(2);
		}
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		더_보낸_메일이_없다();

		확인한다(purpose, link1).andExpect(status().isNoContent());
	}

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("발급 실행기가 그 발급 작업을 버린다 — 링크 1 로 확인하면 204 이고 새 행이 없다")
	void 발급_작업이_버려지면_새_행이_없다(TokenPurpose purpose) throws Exception {
		String email = 이메일("issue-discard", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);

		try (BlockedExecutor blocked = BlockedExecutor.block(this.issueExecutor).fill()) {
			요청한다(purpose, email);
		}
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);

		assertThat(행(accountId, purpose)).as("새 행이 없다").extracting(row -> row.get("token_hash"))
				.containsExactly(AccountTokens.hash(link1));
		확인한다(purpose, link1).andExpect(status().isNoContent());
	}

	/**
	 * 발송 실행기를 막아 두 발급이 모두 커밋된 뒤 두 발송이 차례로 성공하게 한다. 먼저 끝난 발송이 지우는 것은 자기보다 id 가
	 * 작은 행이라 나중 토큰이 산다. 먼저 링크와 링크 1 을 먼저 확인한다 — 그것이 잘못 204 이면 나머지 지우기가 나중 토큰도 지운다.
	 */
	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("같은 계정·목적의 두 발급이 모두 커밋된 뒤 두 발송이 차례로 성공한다 — 나중 링크 204, 먼저 링크와 링크 1 은 AU007")
	void 겹친_두_발급에서_나중_링크가_산다(TokenPurpose purpose) throws Exception {
		String email = 이메일("overlap", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);

		try (BlockedExecutor blocked = BlockedExecutor.block(this.sendExecutor)) {
			요청한다(purpose, email);
			요청한다(purpose, email);
			MailExecutorDrain.drainOnly(this.issueExecutor);
			assertThat(행(accountId, purpose)).as("두 발급이 모두 커밋됐다").hasSize(3);
		}
		String earlier = 링크의_토큰(purpose, this.inMemoryMailer.next(Duration.ofSeconds(5)));
		String later = 링크의_토큰(purpose, this.inMemoryMailer.next(Duration.ofSeconds(5)));
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);

		링크_토큰_오류다(확인한다(purpose, link1));
		링크_토큰_오류다(확인한다(purpose, earlier));
		확인한다(purpose, later).andExpect(status().isNoContent());
	}

	// --- 확인이 나머지를 지운다 ---

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("발송 실패 뒤 링크 1 로 확인한다 — 204 이고 같은 계정·목적의 행은 쓴 토큰 하나다. 다른 목적의 행은 그대로다")
	void 발송_실패_뒤_확인하면_나머지가_지워진다(TokenPurpose purpose) throws Exception {
		String email = 이메일("confirm-rest", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		TokenPurpose other = 다른_목적(purpose);
		String otherToken = 토큰을_심는다(accountId, other);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);
		try (InMemoryMailer.Failing failing = this.inMemoryMailer.failing()) {
			요청한다(purpose, email);
			MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		}
		assertThat(행(accountId, purpose)).hasSize(2);

		확인한다(purpose, link1).andExpect(status().isNoContent());

		assertThat(행(accountId, purpose)).as("쓴 토큰 하나만 남는다").extracting(row -> row.get("token_hash"))
				.containsExactly(AccountTokens.hash(link1));
		assertThat(행(accountId, other)).as("다른 목적의 행은 그대로다").extracting(row -> row.get("token_hash"))
				.containsExactly(AccountTokens.hash(otherToken));
	}

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("확인이 되돌려진다(탈퇴 계정) — 400 AU007 이고 같은 계정·목적의 행이 그대로다")
	void 확인이_되돌려지면_행이_그대로다(TokenPurpose purpose) throws Exception {
		String email = 이메일("rollback", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);
		try (InMemoryMailer.Failing failing = this.inMemoryMailer.failing()) {
			요청한다(purpose, email);
			MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		}
		List<Map<String, Object>> before = 행(accountId, purpose);
		탈퇴시킨다(email);

		링크_토큰_오류다(확인한다(purpose, link1));

		assertThat(행(accountId, purpose)).as("사용 처리도 지우기도 없다").isEqualTo(before)
				.allSatisfy(row -> assertThat(row.get("used_at")).isNull());
	}

	/**
	 * 완료 기준 (b) 「확인의 지우기에서 난 락 예외를 잡아 삼키지 않는다」. 대역이 나머지 지우기에서 락 예외를 던진다. 확인 전체가
	 * 되돌려져 500 {@code C005} 와 마지막 그물의 ERROR 한 줄로 끝나고, 토큰 사용·인증 시각·비밀번호도 되돌려진다 — 그래서 대역을
	 * 걷고 링크 1 을 다시 확인하면 204 다.
	 */
	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("확인의 나머지 지우기가 락 예외를 던진다(대역) — 500 C005, 행이 그대로이고 링크 1 을 다시 확인하면 204 다")
	void 확인의_지우기가_락_예외면_확인이_되돌려진다(TokenPurpose purpose) throws Exception {
		String email = 이메일("lock", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);
		try (InMemoryMailer.Failing failing = this.inMemoryMailer.failing()) {
			요청한다(purpose, email);
			MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		}
		List<Map<String, Object>> rowsBefore = 행(accountId, purpose);
		Map<String, Object> accountBefore = 계정_행(accountId);
		willThrow(new CannotAcquireLockException("Deadlock found when trying to get lock (test double)"))
				.given(this.accountTokenRepository).deleteOthers(any(), any(), any());

		ListAppender<ILoggingEvent> appender = 로그를_모은다(GlobalExceptionHandler.class);
		try {
			확인한다(purpose, link1)
					.andExpect(status().isInternalServerError())
					.andExpect(jsonPath("$.error.code").value("C005"));
		} finally {
			로그를_뗀다(GlobalExceptionHandler.class, appender);
		}

		assertThat(appender.list).filteredOn(event -> event.getLevel() == Level.ERROR)
				.extracting(ILoggingEvent::getFormattedMessage).containsExactly("unhandled exception");
		assertThat(행(accountId, purpose)).as("토큰 사용이 되돌려지고 지운 행도 없다").isEqualTo(rowsBefore)
				.allSatisfy(row -> assertThat(row.get("used_at")).isNull());
		assertThat(계정_행(accountId)).as("인증 시각·비밀번호도 되돌려졌다").isEqualTo(accountBefore);

		Mockito.reset(this.accountTokenRepository);
		확인한다(purpose, link1).andExpect(status().isNoContent());
	}

	// --- 발송 뒤의 지우기가 실패한다 ---

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("발송 뒤의 지우기가 실패한다(대역) — 메일 1통, WARN 한 줄(계정 id·목적), 두 행이 그대로이고 「발송 실패」 줄이 없다")
	void 발송_뒤의_지우기가_실패하면_둘_다_둔다(TokenPurpose purpose) throws Exception {
		String email = 이메일("delete-fail", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);
		willThrow(new CannotAcquireLockException("Lock wait timeout exceeded (test double) " + email))
				.given(this.accountTokenRepository).deletePreceding(any(), any(), any());

		String link2;
		List<String> warnings;
		ListAppender<ILoggingEvent> appender = 로그를_모은다(MailDispatcher.class);
		try {
			요청한다(purpose, email);
			link2 = 링크의_토큰(purpose, this.inMemoryMailer.next(Duration.ofSeconds(5)));
			MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
			warnings = 경고들(appender);
		} finally {
			로그를_뗀다(MailDispatcher.class, appender);
		}

		더_보낸_메일이_없다();
		assertThat(warnings).singleElement().asString()
				.contains("after-send work failed", "accountId=" + accountId, "purpose=" + purpose,
						CannotAcquireLockException.class.getName())
				.doesNotContain("mail send failed", email, link1, link2, "#token=", FRONTEND_BASE_URL);
		assertThat(행(accountId, purpose)).as("두 행이 그대로다").extracting(row -> row.get("token_hash"))
				.containsExactlyInAnyOrder(AccountTokens.hash(link1), AccountTokens.hash(link2));
	}

	// --- 발송 상한·발급의 되돌림 ---

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("발송 상한을 넘는 요청 — 새 행·메일이 없고 WARN 이다. 링크 1 이 204 다")
	void 발송_상한을_넘으면_링크_1_이_산다(TokenPurpose purpose) throws Exception {
		String email = 이메일("limit", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		요청하고_토큰을_꺼낸다(purpose, email);
		요청하고_토큰을_꺼낸다(purpose, email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);

		List<String> warnings;
		ListAppender<ILoggingEvent> appender = 로그를_모은다(AccountTokenIssuer.class);
		try {
			요청한다(purpose, email);
			MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
			warnings = 경고들(appender);
		} finally {
			로그를_뗀다(AccountTokenIssuer.class, appender);
		}

		더_보낸_메일이_없다();
		assertThat(warnings).singleElement().asString().contains("send limit", "accountId=" + accountId);
		assertThat(행(accountId, purpose)).as("새 행이 없다").extracting(row -> row.get("token_hash"))
				.containsExactly(AccountTokens.hash(link1));
		확인한다(purpose, link1).andExpect(status().isNoContent());
	}

	@ParameterizedTest(name = "{displayName} [{0}]")
	@EnumSource(TokenPurpose.class)
	@DisplayName("발급 트랜잭션이 되돌려진다(대역) — 메일이 없고 링크 1 이 204 다")
	void 발급이_되돌려지면_링크_1_이_산다(TokenPurpose purpose) throws Exception {
		String email = 이메일("issue-rollback", purpose);
		Long accountId = 미인증_계정을_만든다(email);
		String link1 = 요청하고_토큰을_꺼낸다(purpose, email);
		willThrow(new DataIntegrityViolationException("insert failed (test double)"))
				.given(this.accountTokenRepository).save(any(AccountToken.class));

		요청한다(purpose, email);
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);

		더_보낸_메일이_없다();
		assertThat(행(accountId, purpose)).extracting(row -> row.get("token_hash"))
				.containsExactly(AccountTokens.hash(link1));
		확인한다(purpose, link1).andExpect(status().isNoContent());
	}

	// --- 도우미 ---

	private static String 이메일(String name, TokenPurpose purpose) {
		return "au24-" + name + "-" + purpose.name().toLowerCase().replace('_', '-') + "@example.com";
	}

	private static TokenPurpose 다른_목적(TokenPurpose purpose) {
		return purpose == TokenPurpose.EMAIL_VERIFICATION ? TokenPurpose.PASSWORD_RESET : TokenPurpose.EMAIL_VERIFICATION;
	}

	private Long 미인증_계정을_만든다(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				// 해시가 아니다. 이 테스트는 로그인하지 않는다 (sp-docs/requirements/member.md §10.2)
				.password("test-not-a-hash-au24")
				.build()).getId();
	}

	private void 탈퇴시킨다(String email) {
		Account account = this.accountRepository.findByEmail(email).orElseThrow();
		account.withdraw();
		this.accountRepository.saveAndFlush(account);
	}

	/** 그 계정의 토큰 행을 심고 원문을 돌려준다. 링크 1 이 아니라 다른 목적의 행을 만들 때 쓴다. */
	private String 토큰을_심는다(Long accountId, TokenPurpose purpose) {
		String token = AccountTokens.generate();
		this.accountTokenRepository.saveAndFlush(AccountToken.issue(accountId, purpose, AccountTokens.hash(token),
				Duration.ofDays(1), this.clock));
		return token;
	}

	/** 앞서 넘어간 일을 비운 뒤 요청하고, 그 메일의 링크에서 토큰을 꺼낸다. 발송이 끝나기까지 기다린다. */
	private String 요청하고_토큰을_꺼낸다(TokenPurpose purpose, String email) throws Exception {
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		this.inMemoryMailer.clear();
		요청한다(purpose, email);
		InMemoryMailer.Sent sent = this.inMemoryMailer.next(Duration.ofSeconds(5));
		assertThat(sent.mail().to()).isEqualTo(email);
		assertThat(sent.mail().purpose()).isEqualTo(purpose.name());
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		return 링크의_토큰(purpose, sent);
	}

	private void 요청한다(TokenPurpose purpose, String email) throws Exception {
		String path = switch (purpose) {
			case EMAIL_VERIFICATION -> "/api/v1/accounts/email-verification";
			case PASSWORD_RESET -> "/api/v1/accounts/password-reset";
		};
		this.mockMvc.perform(json(path, "{\"email\": \"" + email + "\"}")).andExpect(status().isAccepted());
	}

	private ResultActions 확인한다(TokenPurpose purpose, String token) throws Exception {
		return switch (purpose) {
			case EMAIL_VERIFICATION -> this.mockMvc.perform(
					json("/api/v1/accounts/email-verification/confirm", "{\"token\": \"" + token + "\"}"));
			case PASSWORD_RESET -> this.mockMvc.perform(json("/api/v1/accounts/password-reset/confirm",
					"{\"token\": \"" + token + "\", \"newPassword\": \"" + NEW_PASSWORD + "\"}"));
		};
	}

	private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder json(String path,
			String body) {
		return post(path).contentType(MediaType.APPLICATION_JSON).characterEncoding(StandardCharsets.UTF_8)
				.content(body);
	}

	private static void 링크_토큰_오류다(ResultActions result) throws Exception {
		result.andExpect(status().isBadRequest()).andExpect(jsonPath("$.error.code").value("AU007"));
	}

	private static String 링크의_토큰(TokenPurpose purpose, InMemoryMailer.Sent sent) {
		Pattern link = purpose == TokenPurpose.EMAIL_VERIFICATION ? VERIFY_LINK : RESET_LINK;
		Matcher matcher = link.matcher(sent.mail().text());
		assertThat(matcher.find()).as("본문에 링크가 있다: " + link.pattern()).isTrue();
		return matcher.group(1);
	}

	/** 그 계정·목적의 커밋된 행. id 차례다. JPA 를 거치지 않는다. */
	private List<Map<String, Object>> 행(Long accountId, TokenPurpose purpose) {
		return this.jdbcTemplate.queryForList(
				"select id, token_hash, used_at from account_token where account_id = ? and purpose = ? order by id",
				accountId, purpose.name());
	}

	private Map<String, Object> 계정_행(Long accountId) {
		return this.jdbcTemplate.queryForMap(
				"select password, email_verified_at, deleted from account where id = ?", accountId);
	}

	/** 실행기들이 빈 뒤에 남은 메일이 없다. */
	private void 더_보낸_메일이_없다() {
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		assertThatThrownBy(() -> this.inMemoryMailer.next(Duration.ZERO)).as("더 보낸 메일이 없다")
				.isInstanceOf(AssertionError.class);
	}

	private static ListAppender<ILoggingEvent> 로그를_모은다(Class<?> loggerClass) {
		ListAppender<ILoggingEvent> appender = new ListAppender<>();
		appender.start();
		((Logger) LoggerFactory.getLogger(loggerClass)).addAppender(appender);
		return appender;
	}

	private static void 로그를_뗀다(Class<?> loggerClass, ListAppender<ILoggingEvent> appender) {
		((Logger) LoggerFactory.getLogger(loggerClass)).detachAppender(appender);
		appender.stop();
	}

	private static List<String> 경고들(ListAppender<ILoggingEvent> appender) {
		return appender.list.stream()
				.filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN))
				.map(ILoggingEvent::getFormattedMessage)
				.toList();
	}

}
