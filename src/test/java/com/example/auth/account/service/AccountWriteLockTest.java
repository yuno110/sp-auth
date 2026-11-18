package com.example.auth.account.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.willAnswer;

import com.example.auth.account.dto.PasswordChangeRequest;
import com.example.auth.account.dto.WithdrawRequest;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.account.support.AccountTokens;
import com.example.auth.auth.dto.LoginRequest;
import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.auth.service.AuthService;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.support.MutableClock;
import com.example.auth.support.RecordingStatementInspector;
import com.example.auth.support.TestRsaKeys;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/**
 * 비밀번호 변경·탈퇴·재설정 확인이 계정을 먼저 잠그는지 본다 — sp-docs/plan/phase2-auth-member.md AU-22 의 검증 표다.
 *
 * <p>모양은 2026-11-17 AU-18 리뷰의 프로브다. 쓰는 쪽을 실제 스레드에서 보내 {@code refresh_token} 을 지운 직후·커밋 전에
 * 세워 두고, 그동안 다른 요청을 또 다른 스레드에서 보낸다({@link #세워_두고_보낸다}). 로그인을 보내는 줄은 그 계정에
 * {@code refresh_token} 행이 없는 상태에서 시작한다 — 행이 있으면 로그인이 그 행을 갱신하고 쓰는 쪽이 읽어 둔 그 행의 id 로
 * 지워, 고치기 전의 코드에서도 행이 남지 않는다(그 계획의 ① 코드 읽기).
 *
 * <p><b>기다림은 H2 의 세션 표로 본다.</b> 잠금을 기다리는 세션은 {@code INFORMATION_SCHEMA.SESSIONS} 의 {@code BLOCKER_ID} 에
 * 그 잠금을 쥔 세션을 단다(AU-22 실측) — 다른 요청의 세션이 쓰는 쪽의 세션을 달면 쓰는 쪽의 트랜잭션을 기다리는 중이다. H2 의 잠금 동작에
 * 기대는 관측이다. 실 MySQL(반복 읽기)의 결과는 이 클래스가 재지 않는다(그 계획 §5.1 — I-08).
 *
 * <p><b>잠금 읽기가 있는지는 변경↔탈퇴 두 줄의 결과 단언이 가린다</b>(재설정 확인의 잠금 읽기는 이 클래스가 아니라
 * {@code AccountServiceTest} 의 재설정 트랜잭션 경계 테스트가 가린다). 「기다렸다」 단언과 로그인 줄은 잠금 읽기가 없어도
 * 통과한다 — {@code refresh_token} 지우기가 앞서 flush 한 계정 UPDATE 가 그 행을 잠그므로, 다른 요청은 그것만으로도 쓰는 쪽을
 * 기다린다(H2 실측, 2026-11-18 — 잠금 읽기를 일반 읽기로 바꾼 변이에서 그 단언들은 녹색이었다). 로그인 줄이 겨누는 것은
 * 지우기가 계정 잠금 아래에 있는 것과 기다린 로그인을 세지 않는 것이다. 지우기의 모양(계정 조건의 DELETE 하나)은
 * {@link #refresh_token_을_지우는_문장} 이 겨눈다 — 계정 잠금이 있으면 로그인은 거기서 멈추므로 H2 에서는 지우기의 모양이
 * 로그인 결과에 드러나지 않는다(같은 날 실측).
 */
@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties = "spring.jpa.properties.hibernate.session_factory.statement_inspector="
		+ "com.example.auth.support.RecordingStatementInspector")
class AccountWriteLockTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	private static final String NEW_PASSWORD = "NewPassw0rd!";

	/** 쓰는 쪽의 스레드 이름. 이 이름의 스레드에서 한 지우기만 선다. */
	private static final String WRITER_THREAD = "au22-writer";

	/** 쓰는 쪽이 서 있는 동안 다른 요청을 보내는 스레드의 이름. */
	private static final String OTHER_THREAD = "au22-other";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 정리가 남긴다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	/** 시계를 멈추는 시각. 로그인의 검증이 카운터를 0 으로 할 때 {@code updated_at} 이 이 값이다. */
	private static final LocalDateTime NOW = LocalDateTime.of(2026, 11, 17, 10, 0, 0);

	private static final MutableClock CLOCK = new MutableClock();

	/** {@code refresh_token} 테이블에 닿는 문장. */
	private static final Pattern REFRESH_TOKEN = Pattern.compile("(?i)\\brefresh_token\\b");

	/** 그 계정의 행을 조건으로 거는 DELETE. 읽어 둔 행을 id 로 지우는 DELETE 는 {@code account_id} 를 조건으로 갖지 않는다. */
	private static final Pattern DELETE_BY_ACCOUNT =
			Pattern.compile("(?is)^\\s*delete\\s+from\\s+refresh_token\\b.*\\bwhere\\b.*\\baccount_id\\s*=\\s*\\?");

	private static final String INSERT_COUNTER =
			"insert into login_attempt (email_key, failed_count, locked_until, updated_at) values (?, ?, ?, ?)";

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	/** 애플리케이션의 {@code Clock} 빈을 {@link #CLOCK} 로 바꾼다 ({@code ClockConfig}). */
	@TestBean
	private Clock clock;

	static Clock clock() {
		return CLOCK;
	}

	/** 쓰는 쪽을 {@code refresh_token} 을 지우는 자리에 세운다. 나머지는 실제 빈에 위임된다. */
	@MockitoSpyBean
	private RefreshTokenRepository spyRefreshTokenRepository;

	/** 이 클래스의 대역을 주입받은 쪽이다. */
	@Autowired
	private AccountService accountService;

	/** 이 클래스의 대역을 주입받은 쪽이다. */
	@Autowired
	private AuthService authService;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private AccountTokenRepository accountTokenRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	/** 커밋된 값을 읽고 심는다. 쓰는 쪽의 트랜잭션 안에서 부르면 그 트랜잭션이 묶은 연결을 쓴다. */
	@Autowired
	private JdbcTemplate jdbcTemplate;

	@BeforeEach
	void 준비() {
		CLOCK.set(NOW);
	}

	/** 만든 행을 지운다. H2 는 테스트 클래스 사이에 공유되므로({@code DB_CLOSE_DELAY=-1}) 계정은 seed 를 남긴다. */
	@AfterEach
	void 정리() {
		CLOCK.reset();
		this.jdbcTemplate.update("delete from account_token");
		this.jdbcTemplate.update("delete from login_attempt");
		this.jdbcTemplate.update("delete from refresh_token");
		this.jdbcTemplate.update("delete from account where email <> ?", ADMIN_EMAIL);
	}

	/**
	 * 검증 표의 로그인 줄들 — 쓰는 쪽이 서 있는 동안 그 계정의 지금 비밀번호로 로그인한다. 로그인의 저장은 계정을 잠금 읽기로
	 * 다시 읽는다({@code AuthService}). 쓰는 쪽이 계정을 먼저 잠갔으면 저장은 그 커밋을 기다리고, 커밋된 해시나
	 * {@code deleted} 를 보고 401 {@code AU003} 으로 끝난다. 기다린 로그인은 세지 않는다(sp-docs/requirements/member.md §12.1 의
	 * 7) — 카운터는 로그인의 검증이 0 으로 한 값 그대로다.
	 */
	@ParameterizedTest(name = "{0} — 로그인")
	@EnumSource(Writer.class)
	@DisplayName("쓰는 쪽이 refresh_token 을 지우고 커밋 전에 선 동안 로그인하면, 로그인은 그 커밋을 기다린 뒤 401 AU003 이고 행이 없다 — 세지 않는다")
	void 서_있는_쓰기_동안의_로그인(Writer writer) throws Exception {
		String email = "au22-login-" + writer.slug + "@example.com";
		Account account = 계정을_만든다(email);
		카운터를_심는다(email, new Counter(2, null, NOW.minusMinutes(1)));
		Runnable 쓰기 = 쓰기(writer, account);
		assertThat(토큰_행_수(account)).as("시작 — 그 계정에 refresh_token 행이 없다").isZero();

		Race race = 세워_두고_보낸다(쓰기, () -> this.authService.login(new LoginRequest(email, RAW_PASSWORD)));

		SoftAssertions softly = new SoftAssertions();
		softly.assertThat(race.other()).as("로그인의 실패 코드 (null 이면 성공)").isEqualTo(ErrorCode.LOGIN_FAILED);
		softly.assertThat(토큰_행_수(account)).as("refresh_token 행").isZero();
		softly.assertThat(race.otherWaited()).as("로그인이 쓰는 쪽의 잠금을 기다렸다").isTrue();
		softly.assertThat(카운터(email)).as("카운터 — 로그인의 검증이 0 으로 한 값").isEqualTo(new Counter(0, null, NOW));
		softly.assertThat(race.writer()).as("쓰는 쪽의 실패 코드 (null 이면 성공)").isNull();
		softly.assertAll();
	}

	/**
	 * 검증 표 — 비밀번호 변경이 서 있는 동안 옛 비밀번호로 탈퇴한다. 탈퇴는 변경의 커밋을 기다리고, 바뀐 해시와 비교해 400
	 * {@code AU004} 다. 탈퇴가 먼저 커밋되면 변경의 쓰기가 읽어 둔 {@code deleted = false} 로 그 행을 다시 써 탈퇴한 계정이
	 * 되살아난다 — {@code Account} 에 바뀐 컬럼만 싣는 설정이 없다 (sp-docs/plan/phase2-auth-member.md AU-22 의 ②).
	 */
	@Test
	@DisplayName("비밀번호 변경이 선 동안 옛 비밀번호로 탈퇴하면, 탈퇴는 변경의 커밋을 기다린 뒤 400 AU004 이고 계정은 새 비밀번호에 deleted = false 다")
	void 서_있는_변경_동안의_탈퇴() throws Exception {
		Account account = 계정을_만든다("au22-change-then-withdraw@example.com");

		Race race = 세워_두고_보낸다(쓰기(Writer.PASSWORD_CHANGE, account),
				() -> this.accountService.withdraw(account.getId(), new WithdrawRequest(RAW_PASSWORD)));

		SoftAssertions softly = new SoftAssertions();
		softly.assertThat(race.other()).as("탈퇴의 실패 코드 (null 이면 성공)").isEqualTo(ErrorCode.PASSWORD_MISMATCH);
		softly.assertThat(race.otherWaited()).as("탈퇴가 변경의 잠금을 기다렸다").isTrue();
		softly.assertThat(커밋된_탈퇴_여부(account)).as("deleted").isFalse();
		softly.assertThat(this.passwordEncoder.matches(NEW_PASSWORD, 커밋된_해시(account))).as("새 비밀번호다").isTrue();
		softly.assertThat(race.writer()).as("변경의 실패 코드 (null 이면 성공)").isNull();
		softly.assertAll();
	}

	/**
	 * 검증 표 — 탈퇴가 서 있는 동안 비밀번호를 바꾼다. 변경은 탈퇴의 커밋을 기다리고, 탈퇴한 계정을 보고 404 {@code AU001} 이다.
	 * 닫힌 행에는 변경이 닿지 않는다 — 비밀번호가 그대로다.
	 */
	@Test
	@DisplayName("탈퇴가 선 동안 비밀번호를 바꾸면, 변경은 탈퇴의 커밋을 기다린 뒤 404 AU001 이고 계정은 deleted = true 다")
	void 서_있는_탈퇴_동안의_변경() throws Exception {
		Account account = 계정을_만든다("au22-withdraw-then-change@example.com");

		Race race = 세워_두고_보낸다(쓰기(Writer.WITHDRAW, account), () -> this.accountService
				.changePassword(account.getId(), new PasswordChangeRequest(RAW_PASSWORD, NEW_PASSWORD)));

		SoftAssertions softly = new SoftAssertions();
		softly.assertThat(race.other()).as("변경의 실패 코드 (null 이면 성공)").isEqualTo(ErrorCode.ACCOUNT_NOT_FOUND);
		softly.assertThat(race.otherWaited()).as("변경이 탈퇴의 잠금을 기다렸다").isTrue();
		softly.assertThat(커밋된_탈퇴_여부(account)).as("deleted").isTrue();
		softly.assertThat(this.passwordEncoder.matches(RAW_PASSWORD, 커밋된_해시(account))).as("옛 비밀번호 그대로다").isTrue();
		softly.assertThat(race.writer()).as("탈퇴의 실패 코드 (null 이면 성공)").isNull();
		softly.assertAll();
	}

	/**
	 * 검증 표 — 쓰는 쪽이 {@code refresh_token} 에 낸 문장. 그 계정의 행을 조건으로 거는 DELETE 하나다. 행을 읽어 두고 읽은 행을
	 * id 로 지우면 읽은 뒤에 커밋된 행은 지우지 못한다. 그 계정에는 지울 행이 하나 있다.
	 */
	@ParameterizedTest(name = "{0} — 문장")
	@EnumSource(Writer.class)
	@DisplayName("쓰는 쪽이 refresh_token 에 내는 문장은 그 계정의 행을 조건으로 거는 DELETE 하나다 — 행을 읽어 id 로 지우지 않는다")
	void refresh_token_을_지우는_문장(Writer writer) {
		Account account = 계정을_만든다("au22-statement-" + writer.slug + "@example.com");
		앞선_세션을_만든다(account);
		Runnable 쓰기 = 쓰기(writer, account);

		RecordingStatementInspector.clear();
		쓰기.run();

		List<String> statements = RecordingStatementInspector.statements();
		assertThat(statements)
				.filteredOn(sql -> REFRESH_TOKEN.matcher(sql).find())
				.as("%s 가 refresh_token 에 낸 문장", writer)
				.singleElement(InstanceOfAssertFactories.STRING)
				.containsPattern(DELETE_BY_ACCOUNT);
		assertThat(토큰_행_수(account)).as("앞선 세션의 행이 지워졌다").isZero();
	}

	// --- 도우미 ---

	/**
	 * 쓰는 쪽을 실제 스레드에서 보내 {@code refresh_token} 을 지운 직후·커밋 전에 세워 두고, 그동안 다른 요청을 또 다른 스레드에서
	 * 보낸다. 다른 요청이 쓰는 쪽의 잠금을 기다리기 시작하거나 끝나면 쓰는 쪽을 잇고, 둘이 끝나기를 기다린다.
	 */
	private Race 세워_두고_보낸다(Runnable 쓰기, Runnable 다른_요청) throws Exception {
		CountDownLatch 섰다 = new CountDownLatch(1);
		CountDownLatch 잇는다 = new CountDownLatch(1);
		AtomicInteger 쓰는_쪽의_세션 = new AtomicInteger();
		Answer<?> real = 실제_빈에_위임한다(this.spyRefreshTokenRepository);
		willAnswer(invocation -> {
			Object deleted = real.answer(invocation);
			if (WRITER_THREAD.equals(Thread.currentThread().getName())) {
				// 쓰는 쪽의 트랜잭션이 묶은 연결의 세션이다
				쓰는_쪽의_세션.set(this.jdbcTemplate.queryForObject("select session_id()", Integer.class));
				섰다.countDown();
				assertThat(잇는다.await(10, TimeUnit.SECONDS)).as("다른 요청을 보낸 뒤 잇는다").isTrue();
			}
			return deleted;
		}).given(this.spyRefreshTokenRepository).deleteByAccountId(anyLong());

		ExecutorService writer = Executors.newSingleThreadExecutor(runnable -> new Thread(runnable, WRITER_THREAD));
		ExecutorService other = Executors.newSingleThreadExecutor(runnable -> new Thread(runnable, OTHER_THREAD));
		try {
			Future<ErrorCode> written = writer.submit(() -> 실패_코드(쓰기));
			assertThat(섰다.await(10, TimeUnit.SECONDS)).as("쓰는 쪽이 refresh_token 을 지운 자리에 섰다").isTrue();
			Future<ErrorCode> answered = other.submit(() -> 실패_코드(다른_요청));
			boolean waited = 기다리거나_끝날_때까지(answered, 쓰는_쪽의_세션.get());
			잇는다.countDown();
			return new Race(written.get(10, TimeUnit.SECONDS), answered.get(10, TimeUnit.SECONDS), waited);
		} finally {
			잇는다.countDown();
			writer.shutdownNow();
			other.shutdownNow();
			writer.awaitTermination(10, TimeUnit.SECONDS);
			other.awaitTermination(10, TimeUnit.SECONDS);
		}
	}

	/**
	 * 다른 요청의 세션이 쓰는 쪽 세션의 잠금을 기다리기 시작했으면 참, 그 전에 다른 요청이 끝났으면 거짓이다. 둘 다 아니면 다른
	 * 요청이 끝나기를 짧게 기다린 뒤 다시 본다.
	 */
	private boolean 기다리거나_끝날_때까지(Future<ErrorCode> 다른_요청, int 쓰는_쪽의_세션) throws InterruptedException {
		long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
		while (System.nanoTime() < deadline) {
			Integer waiting = this.jdbcTemplate.queryForObject(
					"select count(*) from information_schema.sessions where blocker_id = ?", Integer.class, 쓰는_쪽의_세션);
			if (waiting > 0) {
				return true;
			}
			try {
				다른_요청.get(10, TimeUnit.MILLISECONDS);
				return false;
			} catch (TimeoutException e) {
				// 아직 기다리지도 끝나지도 않았다
			} catch (ExecutionException e) {
				return false;
			}
		}
		return fail("다른 요청이 10초 안에 쓰는 쪽을 기다리지도 끝나지도 않았다");
	}

	/** 요청을 부르고 업무 오류의 코드를 돌려준다 — 성공하면 {@code null} 이다. 그 밖의 예외는 그대로 던진다. */
	private static ErrorCode 실패_코드(Runnable 요청) {
		try {
			요청.run();
			return null;
		} catch (BusinessException e) {
			return e.getErrorCode();
		}
	}

	/** 그 계정의 지금 비밀번호로 부르는 쓰는 쪽. 재설정 확인이면 토큰을 먼저 심는다. */
	private Runnable 쓰기(Writer writer, Account account) {
		return switch (writer) {
			case PASSWORD_CHANGE -> () -> this.accountService
					.changePassword(account.getId(), new PasswordChangeRequest(RAW_PASSWORD, NEW_PASSWORD));
			case WITHDRAW -> () -> this.accountService.withdraw(account.getId(), new WithdrawRequest(RAW_PASSWORD));
			case PASSWORD_RESET -> {
				String token = 재설정_토큰을_심는다(account);
				yield () -> this.accountService.confirmPasswordReset(token, NEW_PASSWORD);
			}
		};
	}

	/**
	 * 스파이의 기본 응답 — 실제 빈에 위임한다. 리포지터리는 JDK 프록시라 {@code callRealMethod()} 를 쓸 수 없고, 스파이는 그 빈을
	 * 이 응답으로 감싼다 ({@code AccountServiceTest} 와 같은 방법).
	 */
	private static Answer<?> 실제_빈에_위임한다(Object spy) {
		return Mockito.mockingDetails(spy).getMockCreationSettings().getDefaultAnswer();
	}

	/** 인증된 계정. 비밀번호는 런타임에 인코딩한다 — 해시를 테스트 파일에 적지 않는다 (sp-docs/requirements/member.md §10.2). */
	private Account 계정을_만든다(String email) {
		Account account = Account.builder().email(email).password(this.passwordEncoder.encode(RAW_PASSWORD)).build();
		account.markEmailVerified(CLOCK);
		return this.accountRepository.saveAndFlush(account);
	}

	/** 그 계정의 앞선 세션 — 로그인이 넣은 {@code refresh_token} 행이 하나 있다. */
	private void 앞선_세션을_만든다(Account account) {
		this.authService.login(new LoginRequest(account.getEmail(), RAW_PASSWORD));
		assertThat(토큰_행_수(account)).as("픽스처 — 앞선 세션").isOne();
	}

	/** 그 계정의 재설정 토큰 행을 심고 원문을 돌려준다. 저장은 해시뿐이다. 수명은 발급 작업의 것을 쓴다. */
	private String 재설정_토큰을_심는다(Account account) {
		String token = AccountTokens.generate();
		this.accountTokenRepository.saveAndFlush(AccountToken.issue(account.getId(), TokenPurpose.PASSWORD_RESET,
				AccountTokens.hash(token), AccountTokenIssuer.PASSWORD_RESET_LIFETIME, CLOCK));
		return token;
	}

	/** 그 이메일의 {@code login_attempt} 행을 SQL 로 심는다. 키는 AU-12 의 변환으로 만든다. */
	private void 카운터를_심는다(String email, Counter counter) {
		this.jdbcTemplate.update(INSERT_COUNTER, LoginAttempt.emailKeyOf(email), counter.failedCount(),
				counter.lockedUntil(), counter.updatedAt());
	}

	/** 그 이메일의 커밋된 {@code login_attempt} 행. 행이 없으면 실패한다. */
	private Counter 카운터(String email) {
		List<Counter> rows = this.jdbcTemplate.query(
				"select failed_count, locked_until, updated_at from login_attempt where email_key = ?",
				(rs, rowNum) -> new Counter(rs.getInt("failed_count"),
						rs.getObject("locked_until", LocalDateTime.class),
						rs.getObject("updated_at", LocalDateTime.class)),
				LoginAttempt.emailKeyOf(email));
		assertThat(rows).as("%s 의 login_attempt 행", email).hasSize(1);
		return rows.get(0);
	}

	/** 그 계정의 커밋된 {@code refresh_token} 행 수. */
	private int 토큰_행_수(Account account) {
		return this.jdbcTemplate.queryForObject(
				"select count(*) from refresh_token where account_id = ?", Integer.class, account.getId());
	}

	private String 커밋된_해시(Account account) {
		return this.jdbcTemplate.queryForObject(
				"select password from account where id = ?", String.class, account.getId());
	}

	private boolean 커밋된_탈퇴_여부(Account account) {
		return this.jdbcTemplate.queryForObject(
				"select deleted from account where id = ?", Boolean.class, account.getId());
	}

	/** {@code refresh_token} 을 지우는 쓰는 쪽. 이름은 테스트의 표시 이름이고, 이메일에는 {@link #slug} 를 쓴다. */
	enum Writer {

		PASSWORD_CHANGE("비밀번호 변경", "password-change"),
		WITHDRAW("탈퇴", "withdraw"),
		PASSWORD_RESET("재설정 확인", "password-reset");

		private final String label;

		private final String slug;

		Writer(String label, String slug) {
			this.label = label;
			this.slug = slug;
		}

		@Override
		public String toString() {
			return this.label;
		}

	}

	/** 서 있던 쓰는 쪽과 그동안 보낸 다른 요청의 실패 코드({@code null} 이면 성공), 다른 요청이 쓰는 쪽을 기다렸는가. */
	private record Race(ErrorCode writer, ErrorCode other, boolean otherWaited) {
	}

	/** {@code login_attempt} 의 연속 실패 수·잠금 시각·마지막 갱신 시각. */
	private record Counter(int failedCount, LocalDateTime lockedUntil, LocalDateTime updatedAt) {
	}

}
