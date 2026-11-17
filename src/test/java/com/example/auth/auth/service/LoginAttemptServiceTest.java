package com.example.auth.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.account.dto.PasswordChangeRequest;
import com.example.auth.account.dto.WithdrawRequest;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.account.service.AccountService;
import com.example.auth.account.support.AccountTokens;
import com.example.auth.auth.dto.LoginRequest;
import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.auth.repository.LoginAttemptRepository;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.support.MutableClock;
import com.example.auth.support.RecordingStatementInspector;
import com.example.auth.support.TestRsaKeys;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.ConnectionHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 로그인 잠금 카운터 빈({@link LoginAttemptService})을 로그인 경로 안에서 본다. sp-docs/plan/phase2-auth-member.md AU-18 의
 * 완료 기준 중 트랜잭션 경계(커밋 분리·최신 커밋 읽기), 세기의 문장과 시각, 다시 하기와 WARN, 세지 않는 경로가 내는
 * 문장이고, 검증 표 중 대역이 필요한 행이다. 정본은 sp-docs/requirements/member.md §12.2 와 sp-docs/domain-model.md §2.5
 * 다. 응답과 카운터 값의 행은 {@link AuthServiceTest} 가 본다.
 *
 * <p>로그인의 저장 트랜잭션도 여기서 본다 — 검증 뒤에 커밋된 비밀번호 변경·재설정·탈퇴를 저장이 보고 세지 않는 것, 그
 * 트랜잭션의 경계와 잠금이다(2026-11-17 AU-18 리뷰가 잰 결함, sp-docs/security.md §5.3). 그 로그인은 실제 스레드에서 보낸다
 * — 로그인이 BCrypt 비교 뒤에 서 있는 동안 끼어드는 쪽이 이 스레드에서 커밋한다.
 *
 * <p>로그인은 애플리케이션의 {@link AuthService} 로 부른다 — 카운터 빈이 불리는 모양 그대로다. 로그인은 바깥 트랜잭션을 열지
 * 않으므로({@link AuthService#login}) 부른 쪽에 트랜잭션이 있을 때의 경계는 카운터 빈을 직접 불러 본다. 응답이 마지막
 * 그물(500 {@code C005}, sp-docs/conventions.md §6.1)에 달린 경로는 HTTP 로 부른다. 트랜잭션 관리자·리포지터리·비밀번호
 * 인코더는 스파이다. 스파이는 실제 빈에 위임하고, 테스트가 끼어드는 자리만 바꾼다.
 *
 * <p><b>다른 연결의 커밋</b>은 트랜잭션이 묶이지 않은 다른 스레드의 {@link JdbcTemplate} 으로 한다 — 곧바로 커밋된다.
 * 끼어드는 자리마다 그 문장이 바꾼 행 수를 본다 — 대역이 아무것도 바꾸지 않으면 그 테스트는 아무것도 보지 않는다.
 * H2 에서는 세기의 트랜잭션이 0행 UPDATE 를 낸 뒤에도 다른 연결의 같은 키 INSERT 가 기다리지 않고 커밋된다(AU-18
 * 실측). MySQL 의 반복 읽기에서는 없는 행을 찾는 그 UPDATE 가 간격 락을 잡을 수 있고 같은 키의 동시 첫 실패가 교착할 수
 * 있다(sp-docs/domain-model.md §2.5 — 교착은 추정이고 실 MySQL 측정 대상이다). 이 클래스의 끼어들기는 간격 락이 없는
 * 격리 수준(예: READ COMMITTED)의 모양이다(정본 §2.5).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "spring.jpa.properties.hibernate.session_factory.statement_inspector="
		+ "com.example.auth.support.RecordingStatementInspector")
class LoginAttemptServiceTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	private static final String WRONG_PASSWORD = "Other1!pw";

	/** 검증 뒤에 끼어드는 비밀번호 변경·재설정의 새 비밀번호. */
	private static final String NEW_PASSWORD = "NewPassw0rd!";

	/** 로그인을 BCrypt 비교 뒤에 세워 두는 스레드의 이름. 이 이름의 스레드에서 한 비교만 선다. */
	private static final String LOGIN_THREAD = "au18-login";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 정리가 남긴다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	/** 시계를 멈추는 시각. 잠금(15분)은 이 시각에 리터럴로 더한다 — 카운터 빈의 상수로 기대값을 만들지 않는다. */
	private static final LocalDateTime LOCK_NOW = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	private static final String INSERT_COUNTER =
			"insert into login_attempt (email_key, failed_count, locked_until, updated_at) values (?, ?, ?, ?)";

	/**
	 * 로그인이 발급한 Refresh Token 을 저장하는 트랜잭션의 이름 — {@link AuthService} 가 그 트랜잭션에 붙인다. 카운터 빈이 연
	 * 트랜잭션은 이름이 없다.
	 */
	private static final String STORE_TRANSACTION = AuthService.class.getName() + ".storeRefreshToken";

	/** 카운터 빈을 직접 부르는 테스트가 바깥에 여는 트랜잭션의 이름. */
	private static final String CALLER_TRANSACTION = "caller";

	/** 잠금 판정의 끝 — 이름 없는 읽기 전용 트랜잭션의 커밋. */
	private static final End 판정의_커밋 = new End("commit", "", true);

	/** 세기·0 으로 하기의 끝 — 이름 없는 트랜잭션의 커밋. */
	private static final End 쓰기의_커밋 = new End("commit", "", false);

	/** 세기가 예외로 끝난 것 — 이름 없는 트랜잭션의 롤백. */
	private static final End 쓰기의_롤백 = new End("rollback", "", false);

	/** 성공한 로그인의 Refresh Token 저장 — 이름 있는 트랜잭션의 커밋. */
	private static final End 저장의_커밋 = new End("commit", STORE_TRANSACTION, false);

	private static final MutableClock CLOCK = new MutableClock();

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

	/** 물리 트랜잭션의 끝이 전부 지나는 곳. {@code isNewTransaction()} 이 참인 끝만 센다. */
	@MockitoSpyBean
	private PlatformTransactionManager spyTransactionManager;

	/** 카운터 빈이 부르는 문장들에 끼어든다. 나머지는 실제 빈에 위임된다. */
	@MockitoSpyBean
	private LoginAttemptRepository spyLoginAttemptRepository;

	/** 로그인이 계정을 읽는 자리에 끼어든다. 나머지는 실제 빈에 위임된다. */
	@MockitoSpyBean
	private AccountRepository spyAccountRepository;

	/** 로그인의 저장이 Refresh Token 을 읽는 자리에 끼어든다. 나머지는 실제 빈에 위임된다. */
	@MockitoSpyBean
	private RefreshTokenRepository spyRefreshTokenRepository;

	/** 검증 뒤에 끼어드는 비밀번호 변경·재설정·탈퇴를 커밋한다 — 이 클래스의 대역들을 주입받은 쪽이다. */
	@Autowired
	private AccountService accountService;

	/** 재설정 토큰을 심는다. */
	@Autowired
	private AccountTokenRepository accountTokenRepository;

	/** 이 클래스의 대역들을 주입받은 쪽이다. */
	@Autowired
	private AuthService authService;

	/** 부른 쪽 트랜잭션 안에서 직접 부른다 — 이 클래스의 대역들을 주입받은 쪽이다. */
	@Autowired
	private LoginAttemptService loginAttemptService;

	/** BCrypt 비교가 끝나는 자리에 끼어든다. 나머지는 실제 빈에 위임된다 — 픽스처의 인코딩도 실제 빈이 한다. */
	@MockitoSpyBean
	private PasswordEncoder spyPasswordEncoder;

	/** 응답이 마지막 그물에 달린 경로를 HTTP 로 부른다. */
	@Autowired
	private MockMvc mockMvc;

	/** 커밋된 값을 읽고 심는다. 테스트 스레드에는 트랜잭션이 없다. */
	@Autowired
	private JdbcTemplate jdbcTemplate;

	/** 트랜잭션에 묶인 연결을 찾는 열쇠다 ({@link TransactionSynchronizationManager#getResource}). */
	@Autowired
	private DataSource dataSource;

	private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

	/** 다른 연결 — 트랜잭션이 묶이지 않은 스레드다. */
	private ExecutorService otherConnection;

	@BeforeEach
	void 준비() {
		CLOCK.set(LOCK_NOW);
		this.otherConnection = Executors.newSingleThreadExecutor();
		this.appender.start();
		counterLogger().addAppender(this.appender);
	}

	/**
	 * 만든 행을 지운다. H2 는 테스트 클래스 사이에 공유되므로({@code DB_CLOSE_DELAY=-1}) {@code account_token} 과
	 * {@code login_attempt} 를 먼저 지우고, 계정은 seed 를 남긴다. 스파이의 대역은 이 메서드 뒤에 풀리므로 SQL 로 지운다.
	 */
	@AfterEach
	void 정리() {
		counterLogger().detachAppender(this.appender);
		this.appender.stop();
		this.otherConnection.shutdownNow();
		CLOCK.reset();
		this.jdbcTemplate.update("delete from account_token");
		this.jdbcTemplate.update("delete from login_attempt");
		this.jdbcTemplate.update("delete from refresh_token");
		this.jdbcTemplate.update("delete from account where email <> ?", ADMIN_EMAIL);
	}

	// --- 커밋 분리 (sp-docs/requirements/member.md §12.2) ---

	/**
	 * 완료 기준 「카운트와 0 으로 되돌리기는 로그인 트랜잭션과 다른 트랜잭션에서 커밋된다 — 실패 응답·{@code AU006} 이 로그인
	 * 트랜잭션을 되돌려도 남는다」. 로그인은 바깥 트랜잭션을 열지 않는다 — 이유는 {@link AuthService#login} 에 있다. 물리
	 * 트랜잭션의 끝을 차례로 세면 카운터 빈이 연 트랜잭션(잠금 판정, 세기)이 각각 커밋되고 그 밖의 트랜잭션은 없다 — 실패는
	 * 저장 트랜잭션을 열지 않는다. 부른 쪽 트랜잭션이 되돌려지는 모양은 {@link #부른_쪽_트랜잭션과_따로_커밋한다()} 가 본다.
	 */
	@Test
	@DisplayName("틀린 비밀번호 — 잠금 판정(읽기 전용)과 세기가 각각 따로 커밋되고, 그 밖의 트랜잭션은 열리지 않는다")
	void 실패의_트랜잭션_경계() {
		String email = "au18-boundary-failure@example.com";
		계정을_만든다(email);
		List<End> ends = 트랜잭션의_끝을_센다();

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD)).isEqualTo(ErrorCode.LOGIN_FAILED);

		assertThat(ends).containsExactly(판정의_커밋, 쓰기의_커밋);
		assertThat(카운터(email)).as("실패 응답의 예외 뒤에도 남았다").isEqualTo(new Counter(1, null, LOCK_NOW));
	}

	@Test
	@DisplayName("맞는 비밀번호 — 0 으로 하기가 따로 커밋된다. 미인증의 AU006 은 저장 트랜잭션을 열지 않고, 성공은 저장 트랜잭션을 따로 커밋한다")
	void 맞는_비밀번호의_트랜잭션_경계() {
		String unverified = "au18-boundary-unverified@example.com";
		String verified = "au18-boundary-verified@example.com";
		미인증_계정을_만든다(unverified);
		계정을_만든다(verified);
		카운터를_심는다(unverified, new Counter(3, null, LOCK_NOW.minusMinutes(1)));
		카운터를_심는다(verified, new Counter(3, null, LOCK_NOW.minusMinutes(1)));
		List<End> ends = 트랜잭션의_끝을_센다();

		assertThat(로그인에_실패한다(unverified, RAW_PASSWORD)).isEqualTo(ErrorCode.EMAIL_NOT_VERIFIED);
		assertThat(ends).as("미인증").containsExactly(판정의_커밋, 쓰기의_커밋);
		assertThat(카운터(unverified)).isEqualTo(new Counter(0, null, LOCK_NOW));

		ends.clear();
		this.authService.login(new LoginRequest(verified, RAW_PASSWORD));
		assertThat(ends).as("성공").containsExactly(판정의_커밋, 쓰기의_커밋, 저장의_커밋);
		assertThat(카운터(verified)).isEqualTo(new Counter(0, null, LOCK_NOW));
	}

	/**
	 * 카운터 빈은 부른 쪽에 트랜잭션이 있어도 판정·세기·0 으로 하기를 저마다 새 트랜잭션에서 커밋한다({@link LoginAttemptService}).
	 * 로그인은 바깥 트랜잭션을 열지 않으므로 로그인 경로로는 이 경계가 드러나지 않는다 — 그래서 카운터 빈을 예외로 되돌려질
	 * 트랜잭션 안에서 직접 부른다. 부른 쪽이 되돌려져도 센 것과 0 으로 한 것이 남고, 판정의 읽기는 부른 쪽 트랜잭션의 연결이
	 * 아니라 읽기 전용 새 트랜잭션의 연결에서 돈다.
	 *
	 * <p>세는 키에는 행을 심어 둔다 — 세기가 조건부 UPDATE 로 끝나 그 키의 행을 읽는 것은 판정뿐이다.
	 */
	@Test
	@DisplayName("부른 쪽 트랜잭션 안에서 불려도 판정·세기·0 으로 하기는 저마다 새 트랜잭션으로 커밋되고, 부른 쪽이 되돌려져도 남는다")
	void 부른_쪽_트랜잭션과_따로_커밋한다() {
		String counted = "au18-caller-count@example.com";
		String reset = "au18-caller-reset@example.com";
		카운터를_심는다(counted, new Counter(1, null, LOCK_NOW.minusMinutes(1)));
		카운터를_심는다(reset, new Counter(3, null, LOCK_NOW.minusMinutes(1)));
		List<Object> 판정의_연결 = new ArrayList<>();
		List<Boolean> 판정의_읽기_전용 = new ArrayList<>();
		Answer<?> attempts = 실제_빈에_위임한다(this.spyLoginAttemptRepository);
		willAnswer(invocation -> {
			판정의_연결.add(묶인_연결());
			판정의_읽기_전용.add(TransactionSynchronizationManager.isCurrentTransactionReadOnly());
			return attempts.answer(invocation);
		}).given(this.spyLoginAttemptRepository).findByEmailKey(anyString());
		TransactionTemplate caller = new TransactionTemplate(this.spyTransactionManager);
		caller.setName(CALLER_TRANSACTION);
		List<Object> 부른_쪽의_연결 = new ArrayList<>();
		IllegalStateException 되돌리는_예외 = new IllegalStateException("부른 쪽을 되돌린다");
		List<End> ends = 트랜잭션의_끝을_센다();

		assertThatThrownBy(() -> caller.executeWithoutResult(status -> {
			부른_쪽의_연결.add(묶인_연결());
			assertThat(this.loginAttemptService.isLocked(counted)).as("판정").isFalse();
			assertThat(this.loginAttemptService.countFailure(counted)).as("세기 — 한도 전").isFalse();
			this.loginAttemptService.reset(reset);
			throw 되돌리는_예외;
		})).isSameAs(되돌리는_예외);

		assertThat(ends).containsExactly(판정의_커밋, 쓰기의_커밋, 쓰기의_커밋, new End("rollback", CALLER_TRANSACTION, false));
		assertThat(카운터(counted)).as("세기").isEqualTo(new Counter(2, null, LOCK_NOW));
		assertThat(카운터(reset)).as("0 으로 하기").isEqualTo(new Counter(0, null, LOCK_NOW));
		assertThat(부른_쪽의_연결).hasSize(1).doesNotContainNull();
		assertThat(판정의_연결).hasSize(1).doesNotContainNull();
		assertThat(판정의_연결.get(0)).as("부른 쪽 트랜잭션의 연결이 아니다").isNotSameAs(부른_쪽의_연결.get(0));
		assertThat(판정의_읽기_전용).containsExactly(true);
	}

	// --- 잠금 판정은 최신 커밋 값을 읽는다 (sp-docs/requirements/member.md §12.2) ---

	/**
	 * 완료 기준 「잠금 판정은 최신 커밋 값을 읽는다 — 로그인 트랜잭션이 먼저 연 스냅샷으로 읽지 않는다」. 로그인은 검증을 트랜잭션
	 * 밖에서 한다 — 계정 조회와 BCrypt 비교 때 스레드에 묶인 트랜잭션이 없으니 판정 전에 열린 스냅샷도 없다. 판정의 읽기는 읽기
	 * 전용 새 트랜잭션의 연결에서 돈다 — 그 트랜잭션의 첫 읽기이므로 MySQL 의 반복 읽기에서도 그때의 최신 커밋을
	 * 본다({@link LoginAttemptService#isLocked}).
	 *
	 * <p>못박는 것은 결과가 아니라 이 구현이 고른 수단이다. 결과 쪽은 {@link #비교_중에_커밋된_잠금을_본다()} 가 본다. 부른 쪽에
	 * 트랜잭션이 있을 때의 판정은 {@link #부른_쪽_트랜잭션과_따로_커밋한다()} 가 본다.
	 */
	@Test
	@DisplayName("계정 조회와 BCrypt 비교는 트랜잭션 밖이고, 잠금 판정은 읽기 전용 새 트랜잭션의 연결에서 읽는다")
	void 검증은_트랜잭션_밖이고_판정은_새_트랜잭션에서_읽는다() {
		String email = "au18-lock-read-connection@example.com";
		계정을_만든다(email);
		List<Boolean> 계정_조회의_트랜잭션 = new ArrayList<>();
		List<Boolean> 비교의_트랜잭션 = new ArrayList<>();
		List<Object> 판정의_연결 = new ArrayList<>();
		List<Boolean> 판정의_읽기_전용 = new ArrayList<>();
		Answer<?> accounts = 실제_빈에_위임한다(this.spyAccountRepository);
		willAnswer(invocation -> {
			계정_조회의_트랜잭션.add(트랜잭션_안이다());
			return accounts.answer(invocation);
		}).given(this.spyAccountRepository).findByEmail(anyString());
		willAnswer(invocation -> {
			Object matched = invocation.callRealMethod();
			비교의_트랜잭션.add(트랜잭션_안이다());
			return matched;
		}).given(this.spyPasswordEncoder).matches(any(), any());
		Answer<?> attempts = 실제_빈에_위임한다(this.spyLoginAttemptRepository);
		willAnswer(invocation -> {
			판정의_연결.add(묶인_연결());
			판정의_읽기_전용.add(TransactionSynchronizationManager.isCurrentTransactionReadOnly());
			return attempts.answer(invocation);
		}).given(this.spyLoginAttemptRepository).findByEmailKey(anyString());

		this.authService.login(new LoginRequest(email, RAW_PASSWORD));

		assertThat(계정_조회의_트랜잭션).as("계정 조회").containsExactly(false);
		assertThat(비교의_트랜잭션).as("BCrypt 비교").containsExactly(false);
		assertThat(판정의_연결).as("성공의 행 읽기는 판정뿐이다").hasSize(1).doesNotContainNull();
		assertThat(판정의_읽기_전용).containsExactly(true);
	}

	/**
	 * 로그인이 계정을 읽은 뒤 BCrypt 비교를 하는 동안 — 비교가 끝나 결과를 돌려주기 직전 — 다른 연결이 잠금을 커밋한다.
	 * 판정은 그 잠금을 보고 맞는 비밀번호도 {@code AU005} 다 (sp-docs/requirements/member.md §12.2). 판정의 읽기가 비교보다
	 * 앞이면 — 계정 조회의 앞이든 뒤든 — 그 잠금을 보지 못한다.
	 *
	 * <p>판정을 비교 전에 열린 트랜잭션에서 읽게 바꿔도 H2 에서는 이 테스트가 통과한다(AU-18 실측) — 그 트랜잭션 안의 읽기도
	 * 그 사이의 커밋을 본다. 그 쪽은 {@link #검증은_트랜잭션_밖이고_판정은_새_트랜잭션에서_읽는다()} 가 본다. MySQL 의 반복
	 * 읽기에서의 결과는 H2 로 보이지 않는다 — 실 MySQL 에서 잴 일이다.
	 */
	@Test
	@DisplayName("BCrypt 비교 중에 다른 연결이 커밋한 잠금을 판정이 본다 — 맞는 비밀번호도 401 AU005 다")
	void 비교_중에_커밋된_잠금을_본다() {
		String email = "au18-lock-during-bcrypt@example.com";
		계정을_만든다(email);
		Counter 끼어든_잠금 = new Counter(0, LOCK_NOW.plusMinutes(15), LOCK_NOW);
		willAnswer(invocation -> {
			Object matched = invocation.callRealMethod();
			assertThat(다른_연결에서_커밋한다(INSERT_COUNTER, LoginAttempt.emailKeyOf(email), 끼어든_잠금.failedCount(),
					끼어든_잠금.lockedUntil(), 끼어든_잠금.updatedAt())).as("끼어든 잠금").isOne();
			return matched;
		}).given(this.spyPasswordEncoder).matches(any(), any());

		assertThat(로그인에_실패한다(email, RAW_PASSWORD)).isEqualTo(ErrorCode.LOGIN_LOCKED);

		assertThat(카운터(email)).isEqualTo(끼어든_잠금);
	}

	// --- 세기의 동시성 자리 (sp-docs/domain-model.md §2.5 의 갱신 문장) ---

	/**
	 * 검증 표 「판정(member.md §12.1 의 3)과 증가 사이에 잠금이 커밋된다(대역)」. 판정은 잠기지 않은 행을 봤고, 증가 직전에
	 * 같은 키의 다른 시도가 다섯째 실패로 잠갔다 — 증가는 0행이고 다시 읽은 행이 잠겨 있다. 응답은 {@code AU005}, 이번
	 * 실패는 세지 않고 잠금을 늘리지 않는다.
	 */
	@Test
	@DisplayName("판정과 증가 사이에 다른 연결이 잠금을 커밋하면 401 AU005 이고 카운터·locked_until 이 그대로다")
	void 판정과_증가_사이의_잠금() {
		String email = "au18-lock-before-increment@example.com";
		계정을_만든다(email);
		카운터를_심는다(email, new Counter(4, null, LOCK_NOW.minusMinutes(1)));
		Counter 끼어든_잠금 = new Counter(0, LOCK_NOW.plusMinutes(15), LOCK_NOW);
		Answer<?> attempts = 실제_빈에_위임한다(this.spyLoginAttemptRepository);
		AtomicInteger increments = new AtomicInteger();
		willAnswer(invocation -> {
			if (increments.incrementAndGet() == 1) {
				assertThat(다른_연결에서_커밋한다(
						"update login_attempt set locked_until = ?, failed_count = 0, updated_at = ? where email_key = ?",
						끼어든_잠금.lockedUntil(), 끼어든_잠금.updatedAt(), LoginAttempt.emailKeyOf(email)))
						.as("끼어든 잠금").isOne();
			}
			return attempts.answer(invocation);
		}).given(this.spyLoginAttemptRepository).incrementFailure(anyString(), any(), any());

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD)).isEqualTo(ErrorCode.LOGIN_LOCKED);

		assertThat(increments).as("다시 하지 않는다").hasValue(1);
		assertThat(카운터(email)).isEqualTo(끼어든_잠금);
		assertThat(경고들()).isEmpty();
	}

	/**
	 * 검증 표 「증가 UPDATE 가 0행이고 잠기지 않은 행이 있다(대역 — domain-model §2.5 의 갱신 문장)」. 행이 없어 증가가
	 * 0행인 직후 같은 키의 동시 첫 실패가 INSERT 를 커밋한다 — 다시 읽은 행은 잠기지 않았다. 그 행을 잠금으로 읽으면 거짓
	 * 잠금이 나고 이번 실패가 사라진다. 새 트랜잭션에서 처음부터 한 번 더 해 끼어든 실패에 이어 센다.
	 */
	@Test
	@DisplayName("증가가 0행인데 잠기지 않은 행이 있으면 새 트랜잭션에서 한 번 더 센다 — 끼어든 실패에 이어 2 다")
	void 영행인데_잠기지_않은_행이면_다시_센다() {
		String email = "au18-retry-unlocked-row@example.com";
		계정을_만든다(email);
		Answer<?> attempts = 실제_빈에_위임한다(this.spyLoginAttemptRepository);
		List<Object> 증가의_트랜잭션 = new ArrayList<>();
		willAnswer(invocation -> {
			증가의_트랜잭션.add(TransactionSynchronizationManager.getResource(this.dataSource));
			Object updated = attempts.answer(invocation);
			if (증가의_트랜잭션.size() == 1) {
				assertThat(updated).as("픽스처 — 행이 없어 0행").isEqualTo(0);
				assertThat(다른_연결에서_커밋한다(INSERT_COUNTER, LoginAttempt.emailKeyOf(email), 1, null, LOCK_NOW))
						.as("끼어든 첫 실패").isOne();
			}
			return updated;
		}).given(this.spyLoginAttemptRepository).incrementFailure(anyString(), any(), any());
		List<End> ends = 트랜잭션의_끝을_센다();

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD)).isEqualTo(ErrorCode.LOGIN_FAILED);

		assertThat(카운터(email)).isEqualTo(new Counter(2, null, LOCK_NOW));
		assertThat(증가의_트랜잭션).hasSize(2).doesNotContainNull();
		assertThat(증가의_트랜잭션.get(1)).as("다시 하기는 다른 트랜잭션이다").isNotSameAs(증가의_트랜잭션.get(0));
		assertThat(ends).containsExactly(판정의_커밋, 쓰기의_커밋, 쓰기의_커밋);
		assertThat(경고들()).isEmpty();
	}

	/**
	 * 검증 표 「다시 하기 — UNIQUE 충돌을 만든다(예: 대역)」 의 기대 「한 번 더 한다」. 이 트랜잭션이 행이 없음을 본 뒤 INSERT
	 * 직전에 같은 키의 동시 첫 실패가 INSERT 를 커밋한다 — 이 INSERT 는 {@code uk_login_attempt_email_key} 에 걸리고 그
	 * 트랜잭션은 되돌려진다. 새 트랜잭션에서 한 번 더 해 끼어든 실패에 이어 센다.
	 */
	@Test
	@DisplayName("INSERT 가 UNIQUE 에 걸리면 그 트랜잭션은 되돌려지고 새 트랜잭션에서 한 번 더 센다 — WARN 이 없다")
	void UNIQUE_충돌이면_다시_센다() {
		String email = "au18-retry-unique@example.com";
		계정을_만든다(email);
		Answer<?> attempts = 실제_빈에_위임한다(this.spyLoginAttemptRepository);
		AtomicInteger inserts = new AtomicInteger();
		willAnswer(invocation -> {
			inserts.incrementAndGet();
			assertThat(다른_연결에서_커밋한다(INSERT_COUNTER, LoginAttempt.emailKeyOf(email), 1, null, LOCK_NOW))
					.as("먼저 커밋된 첫 실패").isOne();
			return attempts.answer(invocation);
		}).given(this.spyLoginAttemptRepository).saveAndFlush(any(LoginAttempt.class));
		List<End> ends = 트랜잭션의_끝을_센다();

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD)).isEqualTo(ErrorCode.LOGIN_FAILED);

		assertThat(inserts).as("다시 하기의 증가는 1행이라 INSERT 하지 않는다").hasValue(1);
		assertThat(카운터(email)).isEqualTo(new Counter(2, null, LOCK_NOW));
		assertThat(ends).containsExactly(판정의_커밋, 쓰기의_롤백, 쓰기의_커밋);
		assertThat(경고들()).isEmpty();
	}

	/**
	 * 검증 표 「다시 하기 — UNIQUE 충돌을 만든다(예: 대역)」 의 기대 「또 실패하면 {@code AU003} 과 WARN 한 줄」 — 응답은
	 * {@code AU003} 그대로이고 세지 못한 실패를 WARN 한 줄로 남긴다 (sp-docs/domain-model.md §2.5). 두 번 다 UNIQUE 에
	 * 걸리게 만든다 — INSERT 직전마다 다른 연결이 그 키를 먼저 넣고, 다시 하기의 증가 직전에는 다른 연결이 그 행을 지운다.
	 * 지우기는 이 상태를 만들려는 대역이다.
	 */
	@Test
	@DisplayName("다시 해도 UNIQUE 에 걸리면 401 AU003 이고 세지 못한 실패를 WARN 한 줄로 남긴다 — 이메일·키가 없다")
	void 다시_해도_UNIQUE_면_WARN_한_줄이다() {
		String email = "au18-retry-unique-twice@example.com";
		String key = LoginAttempt.emailKeyOf(email);
		계정을_만든다(email);
		Answer<?> attempts = 실제_빈에_위임한다(this.spyLoginAttemptRepository);
		AtomicInteger increments = new AtomicInteger();
		willAnswer(invocation -> {
			if (increments.incrementAndGet() == 2) {
				assertThat(다른_연결에서_커밋한다("delete from login_attempt where email_key = ?", key))
						.as("지운 행").isOne();
			}
			return attempts.answer(invocation);
		}).given(this.spyLoginAttemptRepository).incrementFailure(anyString(), any(), any());
		AtomicInteger inserts = new AtomicInteger();
		willAnswer(invocation -> {
			inserts.incrementAndGet();
			assertThat(다른_연결에서_커밋한다(INSERT_COUNTER, key, 1, null, LOCK_NOW)).as("먼저 커밋된 첫 실패").isOne();
			return attempts.answer(invocation);
		}).given(this.spyLoginAttemptRepository).saveAndFlush(any(LoginAttempt.class));
		List<End> ends = 트랜잭션의_끝을_센다();

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD)).isEqualTo(ErrorCode.LOGIN_FAILED);

		assertThat(increments).as("한 번만 다시 한다").hasValue(2);
		assertThat(inserts).hasValue(2);
		assertThat(ends).containsExactly(판정의_커밋, 쓰기의_롤백, 쓰기의_롤백);
		assertThat(카운터(email)).as("다른 연결이 넣은 행뿐이다 — 이번 실패는 세지 못했다")
				.isEqualTo(new Counter(1, null, LOCK_NOW));
		ILoggingEvent warning = 경고_한_줄();
		assertThat(warning.getFormattedMessage()).contains("login failure not counted").doesNotContain(email, key);
		assertThat(warning.getThrowableProxy()).as("예외를 붙이면 메시지와 스택이 함께 남는다").isNull();
	}

	/**
	 * 세기가 락 경합으로 실패하면(예: 교착) 다시 하지 않고, 응답은 {@code AU003} 이며 세지 못한 실패를 WARN 한 줄로 남긴다.
	 * 정본(sp-docs/domain-model.md §2.5)이 다시 하는 자리로 꼽은 것은 「다시 하는 자리(UNIQUE 충돌, 잠기지 않은 행)는 새
	 * 트랜잭션이다」 의 괄호 안이고, 교착은 「한 번 더 해도 실패하면(예: 교착) 로그인 응답은 {@code AU003} 그대로이고 세지 못한
	 * 실패를 WARN 으로 남긴다」 에 있다. WARN 줄에는 예외의 클래스만 있다 — 예외의 메시지에는 키가 실릴 수 있다. 대역의 예외는
	 * 메시지에 키를 싣는다.
	 *
	 * <p>MySQL 의 교착(1213)과 잠금 대기 시간 초과(1205)는 다른 스프링 예외로 온다 — 2026-11-17 AU-18 리뷰가 애플리케이션의
	 * jar 로 확인했다(애플리케이션의 {@code HibernateJpaDialect} 가 Hibernate {@code MySQLDialect} 의 변환을 쓴다). 1213 은
	 * {@link CannotAcquireLockException} 이고 1205 는 {@link PessimisticLockingFailureException} 그 자체다. 둘 다 본다 —
	 * 1213 만 보면 잡는 예외를 {@link CannotAcquireLockException} 으로 좁혀도 통과한다.
	 *
	 * <p>락 경합이 아닌 DB 실패는 삼키지 않는다 — {@link #세기가_연결을_얻지_못하면_500_이다()} 와
	 * {@link #세기의_문장이_락_경합이_아닌_이유로_실패하면_500_이다()} 가 본다.
	 */
	@ParameterizedTest(name = "MySQL {0}")
	@ValueSource(ints = {1213, 1205})
	@DisplayName("세기가 락 경합(교착·잠금 대기 시간 초과)으로 실패하면 다시 하지 않고 401 AU003 이며, WARN 한 줄에 예외의 클래스만 남는다")
	void 세기의_락_경합은_다시_하지_않고_WARN_이다(int mysqlErrorCode) {
		String email = "au18-count-lock-contention@example.com";
		String key = LoginAttempt.emailKeyOf(email);
		계정을_만든다(email);
		Counter 쌓인_카운터 = new Counter(2, null, LOCK_NOW.minusMinutes(1));
		카운터를_심는다(email, 쌓인_카운터);
		PessimisticLockingFailureException 락_경합 = 락_경합(mysqlErrorCode, key);
		willThrow(락_경합).given(this.spyLoginAttemptRepository).incrementFailure(anyString(), any(), any());
		List<End> ends = 트랜잭션의_끝을_센다();

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD)).isEqualTo(ErrorCode.LOGIN_FAILED);

		verify(this.spyLoginAttemptRepository, times(1)).incrementFailure(anyString(), any(), any());
		assertThat(ends).containsExactly(판정의_커밋, 쓰기의_롤백);
		assertThat(카운터(email)).isEqualTo(쌓인_카운터);
		ILoggingEvent warning = 경고_한_줄();
		assertThat(warning.getFormattedMessage())
				.contains("login failure not counted", 락_경합.getClass().getName(), SQLException.class.getName())
				.doesNotContain(email, key, "Deadlock found", "Lock wait timeout");
		assertThat(warning.getThrowableProxy()).as("예외를 붙이면 메시지와 스택이 함께 남는다").isNull();
	}

	// --- 락 경합이 아닌 DB 실패는 삼키지 않는다 (sp-docs/conventions.md §6.1) ---

	/**
	 * 세기의 트랜잭션이 연결을 얻지 못하면 500 {@code C005} 다 — 마지막 그물이 받는다(sp-docs/conventions.md §6.1). 락 경합이
	 * 아니므로 {@code AU003} 으로 삼키지 않는다 — 삼키면 DB 가 실패하는 동안의 실패가 세지지 않은 채 보통의 실패 응답으로
	 * 나간다. 대역은 읽기 전용이 아닌 트랜잭션을 열 때 2026-11-16 AU-18 리뷰가 풀이 마른 때 잰 예외를 던진다 — 판정의 읽기
	 * 전용 트랜잭션은 그대로 열린다.
	 */
	@Test
	@DisplayName("세기의 트랜잭션이 연결을 얻지 못하면 500 C005 이고 카운터가 그대로다 — AU003 으로 삼키지 않는다")
	void 세기가_연결을_얻지_못하면_500_이다() throws Exception {
		String email = "au18-count-no-connection@example.com";
		계정을_만든다(email);
		Counter 쌓인_카운터 = new Counter(2, null, LOCK_NOW.minusMinutes(1));
		카운터를_심는다(email, 쌓인_카운터);
		willThrow(new CannotCreateTransactionException("픽스처 — 연결을 얻지 못했다"))
				.given(this.spyTransactionManager)
				.getTransaction(argThat(definition -> definition != null && !definition.isReadOnly()));

		로그인_요청(email, WRONG_PASSWORD)
				.andExpect(status().isInternalServerError())
				.andExpect(jsonPath("$.error.code").value("C005"));

		assertThat(카운터(email)).isEqualTo(쌓인_카운터);
		assertThat(경고들()).isEmpty();
	}

	/**
	 * 세기의 문장이 락 경합이 아닌 이유로 실패해도 500 {@code C005} 다 — 다시 하지 않고 삼키지도 않는다. 대역은 그 문장이 DB
	 * 자원의 실패를 던지게 한다.
	 */
	@Test
	@DisplayName("세기의 문장이 락 경합이 아닌 DB 실패를 내면 500 C005 이고 카운터가 그대로다 — 다시 하지 않는다")
	void 세기의_문장이_락_경합이_아닌_이유로_실패하면_500_이다() throws Exception {
		String email = "au18-count-statement-failure@example.com";
		계정을_만든다(email);
		Counter 쌓인_카운터 = new Counter(2, null, LOCK_NOW.minusMinutes(1));
		카운터를_심는다(email, 쌓인_카운터);
		willThrow(new DataAccessResourceFailureException("픽스처 — 세기의 문장이 실패했다"))
				.given(this.spyLoginAttemptRepository).incrementFailure(anyString(), any(), any());

		로그인_요청(email, WRONG_PASSWORD)
				.andExpect(status().isInternalServerError())
				.andExpect(jsonPath("$.error.code").value("C005"));

		verify(this.spyLoginAttemptRepository, times(1)).incrementFailure(anyString(), any(), any());
		assertThat(카운터(email)).isEqualTo(쌓인_카운터);
		assertThat(경고들()).isEmpty();
	}

	/**
	 * 잠금 판정의 읽기가 실패하면 500 {@code C005} 다 — 잠기지 않은 것으로 삼으면 잠긴 계정의 맞는 비밀번호가 토큰을 받고,
	 * 이어지는 0 으로 하기가 잠금을 지운다. 잠긴 행을 심고 맞는 비밀번호로 부른다.
	 */
	@Test
	@DisplayName("잠금 판정의 읽기가 실패하면 500 C005 이고 잠금이 그대로다 — 잠긴 계정의 맞는 비밀번호가 토큰을 받지 않는다")
	void 판정의_DB_실패는_500_이고_잠금이_열리지_않는다() throws Exception {
		String email = "au18-lock-read-failure@example.com";
		Account account = 계정을_만든다(email);
		Counter 잠긴_카운터 = new Counter(0, LOCK_NOW.plusMinutes(10), LOCK_NOW.minusMinutes(5));
		카운터를_심는다(email, 잠긴_카운터);
		willThrow(new DataAccessResourceFailureException("픽스처 — 판정의 읽기가 실패했다"))
				.given(this.spyLoginAttemptRepository).findByEmailKey(anyString());

		로그인_요청(email, RAW_PASSWORD)
				.andExpect(status().isInternalServerError())
				.andExpect(jsonPath("$.error.code").value("C005"));

		assertThat(카운터(email)).isEqualTo(잠긴_카운터);
		assertThat(토큰_행_수(account)).isZero();
	}

	/** 0 으로 하기가 실패하면 500 {@code C005} 다 — 삼키면 쌓인 실패를 남긴 채 토큰을 발급한다. */
	@Test
	@DisplayName("0 으로 하기가 실패하면 500 C005 이고 카운터가 그대로다 — 토큰을 발급하지 않는다")
	void 영으로_하기의_DB_실패는_500_이다() throws Exception {
		String email = "au18-reset-failure@example.com";
		Account account = 계정을_만든다(email);
		Counter 쌓인_카운터 = new Counter(3, null, LOCK_NOW.minusMinutes(1));
		카운터를_심는다(email, 쌓인_카운터);
		willThrow(new DataAccessResourceFailureException("픽스처 — 0 으로 하기가 실패했다"))
				.given(this.spyLoginAttemptRepository).reset(anyString(), any(Clock.class));

		로그인_요청(email, RAW_PASSWORD)
				.andExpect(status().isInternalServerError())
				.andExpect(jsonPath("$.error.code").value("C005"));

		assertThat(카운터(email)).isEqualTo(쌓인_카운터);
		assertThat(토큰_행_수(account)).isZero();
	}

	// --- 세기의 문장과 시각 (sp-docs/domain-model.md §2.5 「실패를 센다」) ---

	/**
	 * 완료 기준 「증가가 잡은 행 락 아래·같은 트랜잭션의 5회 판정, 읽고 비교한 뒤 쓰지 않는다」. 다섯째 실패가
	 * {@code login_attempt} 에 내는 문장은 판정의 읽기, 조건부 증가, 조건부 잠금 차례다 — 세기는 그 행을 읽지 않고 두
	 * 조건부 UPDATE 로 끝난다. 증가와 잠금은 한 트랜잭션이고 그 트랜잭션 하나가 커밋된다.
	 */
	@Test
	@DisplayName("다섯째 실패는 판정의 읽기 → 증가 → 잠금 차례로 문장을 내고, 증가와 잠금은 한 트랜잭션이다 — 401 AU005")
	void 다섯째_실패는_한_트랜잭션에서_증가한_뒤_잠근다() {
		String email = "au18-increment-then-lock@example.com";
		계정을_만든다(email);
		카운터를_심는다(email, new Counter(4, null, LOCK_NOW.minusMinutes(1)));
		Answer<?> attempts = 실제_빈에_위임한다(this.spyLoginAttemptRepository);
		List<Object> 쓰기의_트랜잭션 = new ArrayList<>();
		willAnswer(invocation -> {
			쓰기의_트랜잭션.add(TransactionSynchronizationManager.getResource(this.dataSource));
			return attempts.answer(invocation);
		}).given(this.spyLoginAttemptRepository).incrementFailure(anyString(), any(), any());
		willAnswer(invocation -> {
			쓰기의_트랜잭션.add(TransactionSynchronizationManager.getResource(this.dataSource));
			return attempts.answer(invocation);
		}).given(this.spyLoginAttemptRepository).lockIfReached(anyString(), anyInt(), any(), any());
		Pattern table = Pattern.compile("(?is)\\blogin_attempt\\b");
		Pattern read = Pattern.compile("(?is)^\\s*select\\b.*\\bfrom\\s+login_attempt\\b");
		Pattern increment = Pattern.compile(
				"(?is)^\\s*update\\s+login_attempt\\b.*\\bset\\s+(\\w+\\.)?failed_count\\s*=\\s*case\\b");
		Pattern lock = Pattern.compile(
				"(?is)^\\s*update\\s+login_attempt\\b.*\\bset\\s+(\\w+\\.)?locked_until\\s*=\\s*\\?");
		List<End> ends = 트랜잭션의_끝을_센다();
		RecordingStatementInspector.clear();

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD)).isEqualTo(ErrorCode.LOGIN_LOCKED);

		assertThat(RecordingStatementInspector.statements())
				.filteredOn(sql -> table.matcher(sql).find())
				.as("login_attempt 의 문장")
				.satisfiesExactly(
						sql -> assertThat(sql).as("판정의 읽기").containsPattern(read),
						sql -> assertThat(sql).as("증가").containsPattern(increment),
						sql -> assertThat(sql).as("잠금").containsPattern(lock));
		assertThat(쓰기의_트랜잭션).hasSize(2).doesNotContainNull();
		assertThat(쓰기의_트랜잭션.get(1)).as("증가와 잠금은 한 트랜잭션이다").isSameAs(쓰기의_트랜잭션.get(0));
		assertThat(ends).containsExactly(판정의_커밋, 쓰기의_커밋);
		assertThat(카운터(email)).isEqualTo(new Counter(0, LOCK_NOW.plusMinutes(15), LOCK_NOW));
	}

	/**
	 * 첫 실패의 INSERT 도 판정 시각을 넣는다 — 정본의 INSERT 는 {@code (:key, 1, NULL, :now)} 다. 증가가 0행을 낸 뒤
	 * INSERT 전에 시계를 다음 초로 넘긴다. INSERT 가 시계를 다시 읽으면 {@code updated_at} 이 1초 늦어 24시간 경계가 그만큼
	 * 판정 시각과 어긋난다.
	 */
	@Test
	@DisplayName("첫 실패의 INSERT 는 판정 시각을 넣는다 — 증가와 INSERT 사이에 시계가 다음 초로 넘어가도")
	void 첫_실패의_INSERT_는_판정_시각이다() {
		String email = "au18-insert-decision-time@example.com";
		계정을_만든다(email);
		Answer<?> attempts = 실제_빈에_위임한다(this.spyLoginAttemptRepository);
		willAnswer(invocation -> {
			Object updated = attempts.answer(invocation);
			assertThat(updated).as("픽스처 — 행이 없어 0행").isEqualTo(0);
			CLOCK.set(LOCK_NOW.plusSeconds(1));
			return updated;
		}).given(this.spyLoginAttemptRepository).incrementFailure(anyString(), any(), any());

		assertThat(로그인에_실패한다(email, WRONG_PASSWORD)).isEqualTo(ErrorCode.LOGIN_FAILED);

		assertThat(카운터(email)).isEqualTo(new Counter(1, null, LOCK_NOW));
	}

	// --- 세지 않는 경로가 내는 문장 ---

	/**
	 * 잠긴 동안의 시도는 세지 않는다 — 판정(sp-docs/requirements/member.md §12.1 의 3)이 세기(4)보다 앞이다. 세기를 판정
	 * 앞으로 옮겨도 응답과 행은 같다 — 잠긴 행에 증가는 0행이고 다시 읽은 행이 잠겨 있어 {@code AU005} 다(AU-18 실측).
	 * 그래서 낸 문장을 본다. 판정의 읽기가 이 필터에 걸리는지도 본다 — 걸리지 않으면 쓰는 문장이 없다는 단언은 아무것도
	 * 보지 않는다.
	 */
	@Test
	@DisplayName("잠긴 동안의 시도는 login_attempt 에 쓰는 문장을 내지 않는다 — 맞는·틀린 비밀번호 모두")
	void 잠긴_동안에는_카운터에_쓰지_않는다() {
		String email = "au18-locked-no-write@example.com";
		계정을_만든다(email);
		Counter 잠긴_카운터 = new Counter(0, LOCK_NOW.plusMinutes(10), LOCK_NOW.minusMinutes(5));
		카운터를_심는다(email, 잠긴_카운터);
		Pattern write = Pattern.compile("(?is)^\\s*(insert\\s+into|update|delete\\s+from)\\s+login_attempt\\b");
		Pattern read = Pattern.compile("(?is)^\\s*select\\b.*\\bfrom\\s+login_attempt\\b");

		for (String password : List.of(WRONG_PASSWORD, RAW_PASSWORD)) {
			String 경로 = WRONG_PASSWORD.equals(password) ? "틀린 비밀번호" : "맞는 비밀번호";
			RecordingStatementInspector.clear();
			assertThat(로그인에_실패한다(email, password)).as(경로).isEqualTo(ErrorCode.LOGIN_LOCKED);
			List<String> statements = RecordingStatementInspector.statements();
			assertThat(statements).filteredOn(sql -> read.matcher(sql).find()).as("%s — 판정의 읽기", 경로).hasSize(1);
			assertThat(statements).filteredOn(sql -> write.matcher(sql).find()).as("%s — 쓰는 문장", 경로).isEmpty();
		}
		assertThat(카운터(email)).isEqualTo(잠긴_카운터);
	}

	/**
	 * 완료 기준 「빈 값·100자 초과는 계정 조회 없이 {@code AU003}·세지 않는다」(sp-docs/requirements/member.md §12.1 의 1).
	 * Hibernate 가 준비한 SQL 이 하나도 없는지 보고, 두 리포지터리를 부르지 않았는지도 본다. 있는 이메일 + 빈 비밀번호도
	 * 같다.
	 */
	@Test
	@DisplayName("빈 값·100자를 넘는 이메일은 401 AU003 이고 SQL 을 하나도 내지 않는다 — 계정 조회도 카운터도 없다")
	void 빈_값과_100자_초과는_DB_일을_하지_않는다() {
		String email = "au18-no-db-work@example.com";
		계정을_만든다(email);
		String hundredOne = "a".repeat(89) + "@example.com";
		assertThat(hundredOne).as("픽스처").hasSize(101);
		Map<String, LoginRequest> 경로 = new LinkedHashMap<>();
		경로.put("101자 이메일", new LoginRequest(hundredOne, RAW_PASSWORD));
		경로.put("이메일 없음", new LoginRequest(null, RAW_PASSWORD));
		경로.put("빈 이메일", new LoginRequest("", RAW_PASSWORD));
		경로.put("공백 이메일", new LoginRequest("   ", RAW_PASSWORD));
		경로.put("있는 이메일 + 비밀번호 없음", new LoginRequest(email, null));
		경로.put("있는 이메일 + 빈 비밀번호", new LoginRequest(email, ""));
		경로.put("있는 이메일 + 공백 비밀번호", new LoginRequest(email, "   "));
		clearInvocations(this.spyAccountRepository, this.spyLoginAttemptRepository);

		경로.forEach((이름, request) -> {
			RecordingStatementInspector.clear();
			assertThat(로그인에_실패한다(request)).as(이름).isEqualTo(ErrorCode.LOGIN_FAILED);
			assertThat(RecordingStatementInspector.statements()).as("%s — 낸 SQL", 이름).isEmpty();
		});
		verifyNoInteractions(this.spyAccountRepository, this.spyLoginAttemptRepository);
		assertThat(키들()).isEmpty();
	}

	// --- 저장은 검증 뒤에 커밋된 비밀번호 변경·재설정·탈퇴를 본다 (sp-docs/security.md §5.3) ---

	/**
	 * 2026-11-17 AU-18 리뷰가 잰 결함의 회귀 테스트다 — 그 리뷰의 재현 그대로 H2 기본 격리에서 실제 스레드의 로그인을 BCrypt
	 * 비교 뒤에 세워 두고 그동안 비밀번호 변경({@code AccountService.changePassword})을 커밋한다. 저장이 계정을 다시 읽지
	 * 않으면 옛 비밀번호의 로그인이 200 이고 {@code refresh_token} 에 행이 남는다 — 그 리뷰의 실측에서는 그 토큰으로 재발급도
	 * 됐다. 비밀번호를 바꾸면 새 세션은 만들 수 없어야 한다 (sp-docs/security.md §5.3).
	 *
	 * <p>저장이 해시가 검증 때와 다른 것을 보고 401 {@code AU003} 으로 끝난다. 앞선 세션의 행은 변경이 지웠고 새 행이 없다.
	 * <b>세지 않는다</b>(2026-11-17 오케스트레이터 결정, 정본 미정) — 검증이 맞는 비밀번호로 0 으로 한 카운터가 그대로이고
	 * 증가 문장이 없다.
	 */
	@Test
	@DisplayName("BCrypt 비교 뒤에 비밀번호 변경이 커밋되면 옛 비밀번호의 로그인은 401 AU003 이고 refresh_token 행이 없다 — 세지 않는다")
	void 비교_뒤에_커밋된_비밀번호_변경() throws Exception {
		String email = "au18-store-password-change@example.com";
		Account account = 계정을_만든다(email);
		앞선_세션을_만든다(account);
		카운터를_심는다(email, new Counter(0, null, LOCK_NOW.minusMinutes(1)));

		ErrorCode code = 비교_뒤에_끼어든다(email, RAW_PASSWORD, () -> {
			this.accountService.changePassword(account.getId(), new PasswordChangeRequest(RAW_PASSWORD, NEW_PASSWORD));
			assertThat(토큰_행_수(account)).as("변경이 앞선 세션의 행을 지웠다").isZero();
		});

		assertThat(code).isEqualTo(ErrorCode.LOGIN_FAILED);
		저장하지_않았고_세지_않았다(email, account);
	}

	/**
	 * 같은 자리에 비밀번호 재설정 확인({@code AccountService.confirmPasswordReset})이 끼어든다 — 재설정도 비밀번호 변경과 같은
	 * 표에 있다 (sp-docs/security.md §5.3). 확인이 커밋한 뒤 저장은 해시가 다른 것을 보고 401 {@code AU003} 이다.
	 */
	@Test
	@DisplayName("BCrypt 비교 뒤에 비밀번호 재설정 확인이 커밋되면 옛 비밀번호의 로그인은 401 AU003 이고 refresh_token 행이 없다 — 세지 않는다")
	void 비교_뒤에_커밋된_비밀번호_재설정() throws Exception {
		String email = "au18-store-password-reset@example.com";
		Account account = 계정을_만든다(email);
		앞선_세션을_만든다(account);
		String token = 재설정_토큰을_심는다(account);
		카운터를_심는다(email, new Counter(0, null, LOCK_NOW.minusMinutes(1)));

		ErrorCode code = 비교_뒤에_끼어든다(email, RAW_PASSWORD, () -> {
			this.accountService.confirmPasswordReset(token, NEW_PASSWORD);
			assertThat(토큰_행_수(account)).as("확인이 앞선 세션의 행을 지웠다").isZero();
		});

		assertThat(code).isEqualTo(ErrorCode.LOGIN_FAILED);
		저장하지_않았고_세지_않았다(email, account);
	}

	/**
	 * 같은 자리에 탈퇴({@code AccountService.withdraw})가 끼어든다. 저장은 탈퇴를 보고 401 {@code AU003} 이다 — 비교 때 맞은
	 * 비밀번호여도 세지 않는다.
	 *
	 * <p><b>이 경합의 응답이 바뀌었다.</b> 저장이 계정을 다시 읽지 않던 코드에서는 이 로그인이 200 이었다(2026-11-17 AU-18
	 * 수정이 이 테스트로 잰 값) — 탈퇴한 계정에 행이 생기고, 그 행으로는 재발급이 {@code deleted} 를 보고 막았다. 정본은 그
	 * 상태를 무해하다고 받아들였다(sp-docs/api-contract.md §2.2 의 탈퇴 표 아래).
	 */
	@Test
	@DisplayName("BCrypt 비교 뒤에 탈퇴가 커밋되면 맞는 비밀번호의 로그인도 401 AU003 이고 refresh_token 행이 없다 — 세지 않는다")
	void 비교_뒤에_커밋된_탈퇴() throws Exception {
		String email = "au18-store-withdraw@example.com";
		Account account = 계정을_만든다(email);
		앞선_세션을_만든다(account);
		카운터를_심는다(email, new Counter(0, null, LOCK_NOW.minusMinutes(1)));

		ErrorCode code = 비교_뒤에_끼어든다(email, RAW_PASSWORD, () -> {
			this.accountService.withdraw(account.getId(), new WithdrawRequest(RAW_PASSWORD));
			assertThat(토큰_행_수(account)).as("탈퇴가 앞선 세션의 행을 지웠다").isZero();
		});

		assertThat(code).isEqualTo(ErrorCode.LOGIN_FAILED);
		저장하지_않았고_세지_않았다(email, account);
	}

	/**
	 * 저장 트랜잭션의 경계와 잠금을 저장이 계정을 견준 뒤 Refresh Token 을 읽는 자리에서 본다.
	 * <ul>
	 *   <li>카운터 빈의 트랜잭션(판정·0 으로 하기)은 이미 커밋됐다 — 저장 트랜잭션과 겹치지 않는다</li>
	 *   <li>풀이 빌려 준 연결은 저장 트랜잭션의 것 하나다 — 로그인 하나가 연결 둘을 쥐지 않는다({@code LoginConnectionPoolTest}
	 *   가 막는 결함)</li>
	 *   <li>다른 연결이 그 계정의 비밀번호를 바꾸는 UPDATE 는 저장의 커밋까지 기다린다 — 견준 값이 저장의 커밋까지 그대로다.
	 *   잠그지 않고 읽으면 그 UPDATE 가 견준 뒤에 먼저 커밋되고, 저장은 바뀌기 전의 해시와 견준 세션을 남긴다</li>
	 * </ul>
	 * 기다리는지는 300ms 안에 끝나는지로 본다 ({@code AccountServiceTest} 와 같은 방법).
	 */
	@Test
	@DisplayName("저장은 카운터 트랜잭션이 커밋된 뒤 연결 하나로 계정을 잠그고, 다른 연결의 계정 쓰기는 저장의 커밋까지 기다린다")
	void 저장은_계정을_잠그고_연결_하나로_커밋한다() throws Exception {
		String email = "au18-store-lock@example.com";
		Account account = 계정을_만든다(email);
		String 바뀐_해시 = this.spyPasswordEncoder.encode(NEW_PASSWORD);
		List<End> ends = 트랜잭션의_끝을_센다();
		List<End> 저장_중에_본_끝 = new ArrayList<>();
		List<Integer> 저장_중의_빌린_연결 = new ArrayList<>();
		List<Boolean> 저장_커밋_전에_끝났다 = new ArrayList<>();
		List<Future<Integer>> 비밀번호_쓰기 = new ArrayList<>();
		Answer<?> refreshTokens = 실제_빈에_위임한다(this.spyRefreshTokenRepository);
		willAnswer(invocation -> {
			저장_중에_본_끝.addAll(ends);
			저장_중의_빌린_연결.add(빌려_준_연결());
			Future<Integer> started = this.otherConnection.submit(() -> this.jdbcTemplate.update(
					"update account set password = ? where id = ?", 바뀐_해시, account.getId()));
			비밀번호_쓰기.add(started);
			저장_커밋_전에_끝났다.add(끝났는가(started, 300));
			return refreshTokens.answer(invocation);
		}).given(this.spyRefreshTokenRepository).findByAccountId(anyLong());

		this.authService.login(new LoginRequest(email, RAW_PASSWORD));

		assertThat(저장_중에_본_끝).as("저장 중에 이미 끝난 트랜잭션").containsExactly(판정의_커밋, 쓰기의_커밋);
		assertThat(저장_중의_빌린_연결).as("저장 중에 풀이 빌려 준 연결").containsExactly(1);
		assertThat(저장_커밋_전에_끝났다).as("다른 연결의 비밀번호 쓰기가 저장의 커밋을 기다렸다").containsExactly(false);
		assertThat(비밀번호_쓰기.get(0).get(5, TimeUnit.SECONDS)).as("비밀번호 쓰기는 저장이 커밋한 뒤에 들어간다").isOne();
		assertThat(ends).containsExactly(판정의_커밋, 쓰기의_커밋, 저장의_커밋);
		assertThat(토큰_행_수(account)).isOne();
	}

	// --- 도우미 ---

	/**
	 * 지금부터 끝나는 물리 트랜잭션을 차례로 모은다. 준비가 끝난 뒤에 부른다. 이름과 읽기 전용 여부는 그 트랜잭션의 상태가
	 * 준다({@link TransactionStatus#getTransactionName()} — 이름이 없으면 빈 문자열).
	 */
	private List<End> 트랜잭션의_끝을_센다() {
		List<End> ends = new CopyOnWriteArrayList<>();
		willAnswer(invocation -> {
			기록한다(ends, "commit", invocation.getArgument(0));
			return invocation.callRealMethod();
		}).given(this.spyTransactionManager).commit(any(TransactionStatus.class));
		willAnswer(invocation -> {
			기록한다(ends, "rollback", invocation.getArgument(0));
			return invocation.callRealMethod();
		}).given(this.spyTransactionManager).rollback(any(TransactionStatus.class));
		return ends;
	}

	private static void 기록한다(List<End> ends, String kind, TransactionStatus status) {
		if (status.isNewTransaction()) {
			ends.add(new End(kind, status.getTransactionName(), status.isReadOnly()));
		}
	}

	/**
	 * 스파이의 기본 응답 — 실제 빈에 위임한다. 리포지터리는 JDK 프록시라 {@code callRealMethod()} 를 쓸 수 없고, 스파이는
	 * 그 빈을 이 응답으로 감싼다 ({@code AccountServiceTest} 와 같은 방법).
	 */
	private static Answer<?> 실제_빈에_위임한다(Object spy) {
		return Mockito.mockingDetails(spy).getMockCreationSettings().getDefaultAnswer();
	}

	/** 지금 스레드에 묶인 트랜잭션의 JDBC 연결. 묶인 트랜잭션이 없으면 {@code null}. */
	private Object 묶인_연결() {
		ConnectionHolder holder = (ConnectionHolder) TransactionSynchronizationManager.getResource(this.dataSource);
		return (holder != null) ? holder.getConnection() : null;
	}

	/** 지금 스레드에 실제 트랜잭션이 있거나 연결이 묶여 있는가. */
	private boolean 트랜잭션_안이다() {
		return TransactionSynchronizationManager.isActualTransactionActive()
				|| TransactionSynchronizationManager.getResource(this.dataSource) != null;
	}

	/** 다른 연결에서 문장 하나를 곧바로 커밋하고 그 결과를 기다린다. 바꾼 행 수를 돌려준다. */
	private int 다른_연결에서_커밋한다(String sql, Object... args) {
		try {
			return this.otherConnection.submit(() -> this.jdbcTemplate.update(sql, args)).get(5, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException(e);
		} catch (ExecutionException | TimeoutException e) {
			throw new IllegalStateException("다른 연결의 문장이 끝나지 않았다", e);
		}
	}

	/** 시간 안에 끝났으면 참, 아니면 거짓. 끝나지 않은 작업을 취소하지 않는다. */
	private static boolean 끝났는가(Future<?> future, long millis) {
		try {
			future.get(millis, TimeUnit.MILLISECONDS);
			return true;
		} catch (TimeoutException e) {
			return false;
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	/** 풀이 지금 빌려 준 연결 수. */
	private int 빌려_준_연결() {
		try {
			return this.dataSource.unwrap(HikariDataSource.class).getHikariPoolMXBean().getActiveConnections();
		} catch (SQLException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * 로그인을 실제 스레드에서 보내 BCrypt 비교 뒤에 세워 두고, 그동안 이 스레드에서 {@code 끼어들기} 를 끝낸 뒤 로그인을
	 * 잇는다. 로그인이 실패한 에러 코드를 돌려준다 — 로그인이 성공하면 테스트가 실패한다. 끼어드는 쪽의 비교는 이 스레드에서
	 * 돌므로 서지 않는다.
	 */
	private ErrorCode 비교_뒤에_끼어든다(String email, String password, Runnable 끼어들기) throws Exception {
		CountDownLatch 비교_뒤 = new CountDownLatch(1);
		CountDownLatch 잇는다 = new CountDownLatch(1);
		willAnswer(invocation -> {
			Object matched = invocation.callRealMethod();
			if (LOGIN_THREAD.equals(Thread.currentThread().getName())) {
				비교_뒤.countDown();
				assertThat(잇는다.await(10, TimeUnit.SECONDS)).as("끼어들기가 끝났다").isTrue();
			}
			return matched;
		}).given(this.spyPasswordEncoder).matches(any(), any());
		ExecutorService login = Executors.newSingleThreadExecutor(runnable -> new Thread(runnable, LOGIN_THREAD));
		try {
			Future<ErrorCode> result = login.submit(() -> 로그인에_실패한다(email, password));
			assertThat(비교_뒤.await(10, TimeUnit.SECONDS)).as("로그인이 BCrypt 비교를 마쳤다").isTrue();
			끼어들기.run();
			잇는다.countDown();
			return result.get(30, TimeUnit.SECONDS);
		} catch (ExecutionException e) {
			if (e.getCause() instanceof AssertionError failure) {
				throw failure;
			}
			throw e;
		} finally {
			잇는다.countDown();
			login.shutdownNow();
		}
	}

	/** 그 계정의 앞선 세션 — {@code refresh_token} 행이 하나 있다. 끼어드는 쪽이 지울 행이다. */
	private void 앞선_세션을_만든다(Account account) {
		this.authService.login(new LoginRequest(account.getEmail(), RAW_PASSWORD));
		assertThat(토큰_행_수(account)).as("픽스처 — 앞선 세션").isOne();
	}

	/**
	 * 그 계정의 재설정 토큰 행을 심고 원문을 돌려준다. 저장은 해시뿐이다 (sp-docs/domain-model.md §2.4). 수명은 정본의
	 * 30분이다 (sp-docs/requirements/member.md §11.1) — 확인은 멈춘 시계의 같은 시각에 돈다.
	 */
	private String 재설정_토큰을_심는다(Account account) {
		String token = AccountTokens.generate();
		this.accountTokenRepository.saveAndFlush(AccountToken.issue(account.getId(), TokenPurpose.PASSWORD_RESET,
				AccountTokens.hash(token), Duration.ofMinutes(30), CLOCK));
		return token;
	}

	/**
	 * 저장이 어긋남을 보고 끝났다 — 그 계정의 {@code refresh_token} 행이 없고, 검증이 맞는 비밀번호로 0 으로 한 카운터가
	 * 그대로이며 증가 문장을 내지 않았다.
	 */
	private void 저장하지_않았고_세지_않았다(String email, Account account) {
		assertThat(토큰_행_수(account)).as("refresh_token 행").isZero();
		assertThat(카운터(email)).as("카운터").isEqualTo(new Counter(0, null, LOCK_NOW));
		verify(this.spyLoginAttemptRepository, never()).incrementFailure(anyString(), any(), any());
	}

	/**
	 * MySQL 의 락 경합이 스프링 예외로 온 모양 — 1213(교착)과 1205(잠금 대기 시간 초과). 예외의 종류와 SQLState 는 2026-11-17
	 * AU-18 리뷰가 애플리케이션의 jar 로 확인한 값이다. 두 메시지에 키를 싣는다 — WARN 줄이 메시지를 옮기면 걸린다.
	 */
	private static PessimisticLockingFailureException 락_경합(int mysqlErrorCode, String key) {
		return switch (mysqlErrorCode) {
			case 1213 -> new CannotAcquireLockException("could not execute statement [" + key + "]",
					new SQLException("Deadlock found when trying to get lock [" + key + "]", "40001", 1213));
			case 1205 -> new PessimisticLockingFailureException("could not execute statement [" + key + "]",
					new SQLException("Lock wait timeout exceeded [" + key + "]", "40001", 1205));
			default -> throw new IllegalArgumentException("픽스처 — 다루지 않는 오류 번호: " + mysqlErrorCode);
		};
	}

	private ErrorCode 로그인에_실패한다(String email, String password) {
		return 로그인에_실패한다(new LoginRequest(email, password));
	}

	private ErrorCode 로그인에_실패한다(LoginRequest request) {
		try {
			this.authService.login(request);
		} catch (BusinessException e) {
			return e.getErrorCode();
		}
		return fail("로그인이 실패해야 한다");
	}

	/** 로그인을 HTTP 로 보낸다 — 예외가 응답 코드로 바뀌는 자리까지 지난다. */
	private ResultActions 로그인_요청(String email, String password) throws Exception {
		return this.mockMvc.perform(post("/api/v1/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content("{\"email\": \"" + email + "\", \"password\": \"" + password + "\"}"));
	}

	/** 인증된 계정. 비밀번호는 런타임에 인코딩한다 — 해시를 테스트 파일에 적지 않는다 (sp-docs/requirements/member.md §10.2). */
	private Account 계정을_만든다(String email) {
		Account account = Account.builder().email(email).password(this.spyPasswordEncoder.encode(RAW_PASSWORD)).build();
		account.markEmailVerified(CLOCK);
		return this.spyAccountRepository.saveAndFlush(account);
	}

	/** {@code email_verified_at} 이 NULL 인 계정. */
	private Account 미인증_계정을_만든다(String email) {
		return this.spyAccountRepository.saveAndFlush(
				Account.builder().email(email).password(this.spyPasswordEncoder.encode(RAW_PASSWORD)).build());
	}

	/** 그 이메일의 {@code login_attempt} 행을 SQL 로 심는다. 키는 AU-12 의 변환으로 만든다. */
	private void 카운터를_심는다(String email, Counter counter) {
		this.jdbcTemplate.update(INSERT_COUNTER, LoginAttempt.emailKeyOf(email), counter.failedCount(),
				counter.lockedUntil(), counter.updatedAt());
	}

	/** 그 이메일의 커밋된 {@code login_attempt} 행. 행이 없으면 실패한다. JPA 를 거치지 않는다. */
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

	/** 그 계정의 커밋된 {@code refresh_token} 행 수. JPA 를 거치지 않는다. */
	private int 토큰_행_수(Account account) {
		return this.jdbcTemplate.queryForObject(
				"select count(*) from refresh_token where account_id = ?", Integer.class, account.getId());
	}

	private List<String> 키들() {
		return this.jdbcTemplate.queryForList("select email_key from login_attempt", String.class);
	}

	/** 카운터 빈의 로그 중 WARN 이상 — ERROR 로 올라간 줄도 걸린다. */
	private List<ILoggingEvent> 경고들() {
		return this.appender.list.stream()
				.filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN))
				.toList();
	}

	/** WARN 이상이 한 줄이고 그 줄이 WARN 이다 — ERROR 로 남기면 실패다. */
	private ILoggingEvent 경고_한_줄() {
		List<ILoggingEvent> warnings = 경고들();
		assertThat(warnings).hasSize(1);
		assertThat(warnings.get(0).getLevel()).as("로그 수준").isEqualTo(Level.WARN);
		return warnings.get(0);
	}

	private static Logger counterLogger() {
		return (Logger) LoggerFactory.getLogger(LoginAttemptService.class);
	}

	/** {@code login_attempt} 의 연속 실패 수·잠금 시각·마지막 갱신 시각. */
	private record Counter(int failedCount, LocalDateTime lockedUntil, LocalDateTime updatedAt) {
	}

	/** 물리 트랜잭션 하나의 끝 — 커밋인지 롤백인지, 그 트랜잭션의 이름, 읽기 전용인지. */
	private record End(String kind, String name, boolean readOnly) {
	}

}
