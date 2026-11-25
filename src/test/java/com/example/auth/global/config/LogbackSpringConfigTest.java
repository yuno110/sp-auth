package com.example.auth.global.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.account.support.AccountTokens;
import com.example.auth.global.error.GlobalExceptionHandler;
import com.example.auth.support.TestRsaKeys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/**
 * {@code src/main/resources/logback-spring.xml} 이 가입의 UNIQUE 충돌({@code uk_account_email})에 Hibernate 가 남기는 ERROR
 * 줄만 버리는지 <b>실제 Hibernate 출력</b>으로 본다 (sp-docs/plan/phase2-auth-member.md AU-25, sp-docs/conventions.md §8.1,
 * sp-docs/tech-stack.md §4.8). 가입의 그 밖의 무결성 위반이 마지막 그물의 ERROR 로 남는 것도 여기서 요청으로 본다.
 *
 * <p><b>필터를 손으로 붙이지 않는다.</b> 받는 쪽은 로거에 단 {@link ListAppender} 이고, 필터는 Boot 가 읽은 설정 파일이 로거
 * 컨텍스트에 건 것이다 — TurboFilter 는 appender 로 가기 전에 로거 컨텍스트에서 판정하므로 버린 줄은 이 appender 에도 오지
 * 않는다. 그래서 설정 파일을 지우거나 필터 줄을 뺀 변이에서 충돌의 「ERROR 0」 이 빨개진다.
 *
 * <p><b>WARN 과 다른 ERROR 를 함께 단언한다.</b> 로거를 끄거나 수준을 올린 변이에서는 「ERROR 0」 이 녹색이다 — 실패할 수 없는
 * 단언이 되지 않게(sp-docs/process/review-policy.md §4.1) 같은 충돌의 WARN 한 줄과, 다른 제약 위반의 ERROR 한 줄이 남는 것을
 * 본다.
 *
 * <p>로거 이름은 리터럴로 적는다 — 필터의 상수를 가져다 쓰면 그 상수를 바꾼 변이에서 받는 쪽이 함께 움직인다. 받은 줄은 이
 * 테스트의 스레드 것만 본다 — MockMvc 는 부르는 스레드에서 요청을 처리하고, 메일 실행기 같은 다른 스레드의 줄이 섞이지 않는다.
 *
 * <p>정리는 이 클래스가 만든 계정({@code au25-} 접두어)과 그 계정의 토큰 행을 지운다. H2 는 테스트 클래스 사이에 공유되므로
 * (sp-docs/tech-stack.md §5.3) seed 는 남긴다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LogbackSpringConfigTest {

	private static final String SQL_EXCEPTION_HELPER = "org.hibernate.engine.jdbc.spi.SqlExceptionHelper";

	/** H2 의 UNIQUE 위반에 그 로거가 남기는 WARN 줄. */
	private static final String H2_UNIQUE_WARN = "SQL Error: 23505, SQLState: 23505";

	/** H2 의 FK 위반에 그 로거가 남기는 WARN 줄. */
	private static final String H2_FK_WARN = "SQL Error: 23506, SQLState: 23506";

	/** 「그 요청이 남긴 줄」 에서 빼는 SQL·바인드 로거 (AU-25 의 검증 표). */
	private static final List<String> SQL_AND_BIND_LOGGERS = List.of("org.hibernate.SQL", "org.hibernate.orm.jdbc.bind");

	private static final String RAW_PASSWORD = "Passw0rd!";

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MockMvc mockMvc;

	/** 사전 검사에 끼워넣기를, 저장에 대역 위반을 거는 자리다. 대역 밖에서는 실제 빈에 위임한다. 스텁은 테스트가 끝나면 지워진다. */
	@MockitoSpyBean
	private AccountRepository accountRepository;

	@Autowired
	private AccountTokenRepository accountTokenRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private Clock clock;

	private final ListAppender<ILoggingEvent> 받은_줄 = new ListAppender<>();

	private Logger sqlExceptionHelper;

	@BeforeEach
	void 로거에_받는_쪽을_단다() {
		this.sqlExceptionHelper = (Logger) LoggerFactory.getLogger(SQL_EXCEPTION_HELPER);
		this.받은_줄.start();
		this.sqlExceptionHelper.addAppender(this.받은_줄);
	}

	@AfterEach
	void 정리() {
		this.sqlExceptionHelper.detachAppender(this.받은_줄);
		this.받은_줄.stop();
		this.jdbcTemplate.update("delete from account_token where account_id in "
				+ "(select id from account where email like 'au25-%')");
		this.jdbcTemplate.update("delete from account where email like 'au25-%'");
	}

	/**
	 * 검증 표 <b>「가입의 {@code uk_account_email} 실제 위반」</b>. 사전 검사의 대역이 같은 이메일의 행을 다른 스레드에서 커밋한 뒤
	 * 「없음」 을 돌려준다 — 그러면 이 요청의 계정 INSERT 가 {@code uk_account_email} 에 실제로 걸린다. 응답은 AU-05 의 기대 그대로다.
	 *
	 * <p><b>그 요청이 남긴 줄을 모두 본다</b> (sp-docs/conventions.md §8.1 의 「버린다」 행 — 잡는 코드가 줄을 더하지 않고, 수준을
	 * 낮춰 다시 남기지 않는다). 루트 logger 에 받는 쪽을 달아 이 스레드의 줄을 모으고 SQL·바인드 로거의 줄은 뺀다. 수준을 낮춰 남긴
	 * 줄도 모이게 앱 패키지의 수준을 이 요청 동안 {@code TRACE} 로 둔다.
	 */
	@Test
	@DisplayName("가입의 uk_account_email 충돌은 409 AU002 이고, 그 로거의 ERROR 없이 WARN 한 줄과 핸들러의 WARN 만 남고 이메일이 없다")
	void 가입의_UNIQUE_충돌은_ERROR_를_남기지_않는다() throws Exception {
		String email = "au25-race@example.com";
		AtomicInteger 끼운_행 = new AtomicInteger(-1);
		willAnswer(invocation -> {
			끼운_행.set(다른_스레드에서_같은_이메일로_넣는다(email));
			return false;
		}).given(this.accountRepository).existsByEmail(email);

		Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
		Logger app = (Logger) LoggerFactory.getLogger("com.example.auth");
		ListAppender<ILoggingEvent> 모든_줄 = new ListAppender<>();
		모든_줄.start();
		Level original = app.getLevel();
		app.setLevel(Level.TRACE);
		root.addAppender(모든_줄);
		try {
			가입한다(email)
					.andExpect(status().isConflict())
					.andExpect(jsonPath("$.error.code").value("AU002"));
		} finally {
			root.detachAppender(모든_줄);
			app.setLevel(original);
			모든_줄.stop();
		}
		String thread = Thread.currentThread().getName();
		List<ILoggingEvent> 그_요청의_줄 = 모든_줄.list.stream()
				.filter(event -> thread.equals(event.getThreadName()))
				.filter(event -> !SQL_AND_BIND_LOGGERS.contains(event.getLoggerName()))
				.toList();

		assertThat(끼운_행.get()).as("끼운 행이 먼저 커밋돼야 이 요청의 INSERT 가 충돌한다").isEqualTo(1);
		assertThat(수준별(Level.ERROR)).as("가입의 UNIQUE 충돌은 그 로거의 ERROR 가 아니다 (§8.1)").isEmpty();
		assertThat(수준별(Level.WARN)).as("충돌의 흔적인 WARN 한 줄은 남는다 (§8.1)").containsExactly(H2_UNIQUE_WARN);
		assertThat(그_요청의_줄)
				.as("그 요청이 남긴 줄은 그 WARN 과 핸들러의 업무 예외 WARN 뿐이다 (§8.1, §6.1)")
				.extracting(ILoggingEvent::getLoggerName, ILoggingEvent::getLevel, ILoggingEvent::getFormattedMessage)
				.containsExactly(
						tuple(SQL_EXCEPTION_HELPER, Level.WARN, H2_UNIQUE_WARN),
						tuple(GlobalExceptionHandler.class.getName(), Level.WARN, "business exception: AU002"));
		assertThat(그_요청의_줄).extracting(LogbackSpringConfigTest::줄의_전부)
				.as("어느 줄에도 그 이메일이 없다 — 예외가 실렸으면 그 원인 사슬의 메시지까지 본다")
				.allSatisfy(line -> assertThat(line).doesNotContainIgnoringCase(email));
	}

	/**
	 * 검증 표 <b>「가입의 계정 INSERT 가 그 밖의 무결성 위반을 낸다」</b>의 요청 쪽 (AU-25 의 (a)). 잡는 코드가 다시 던진 위반이
	 * 마지막 그물에 닿아 500 {@code C005} 와 ERROR {@code unhandled exception} 이 된다 (sp-docs/conventions.md §6.1). 위반은 원인
	 * 사슬에 다른 제약의 이름(PK)을 실은 대역이다 — 요청으로는 계정 INSERT 가 그 밖의 위반을 내는 경로를 H2 로 만들 수 없다(길이 초과는
	 * DTO 검증이 먼저 막는다). 문면은 MySQL 의
	 * 것을 본떴다. 서비스 쪽의 모양별 대역은 {@code AccountServiceTest} 가 본다.
	 */
	@Test
	@DisplayName("가입의 그 밖의 무결성 위반은 500 C005 이고 마지막 그물이 그 위반을 ERROR 로 남긴다")
	void 가입의_그_밖의_무결성_위반은_마지막_그물에_닿는다() throws Exception {
		DataIntegrityViolationException violation = new DataIntegrityViolationException("could not execute statement",
				new ConstraintViolationException("could not execute statement",
						new SQLException("Duplicate entry '7' for key 'account.PRIMARY'", "23000", 1062),
						"insert into account (created_at,deleted,email,email_verified_at,password,role,updated_at) "
								+ "values (?,?,?,?,?,?,?)",
						"account.PRIMARY"));
		willThrow(violation).given(this.accountRepository).saveAndFlush(any(Account.class));

		Logger handler = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
		ListAppender<ILoggingEvent> 핸들러의_줄 = new ListAppender<>();
		핸들러의_줄.start();
		handler.addAppender(핸들러의_줄);
		try {
			가입한다("au25-other@example.com")
					.andExpect(status().isInternalServerError())
					.andExpect(jsonPath("$.error.code").value("C005"));
		} finally {
			handler.detachAppender(핸들러의_줄);
			핸들러의_줄.stop();
		}

		assertThat(핸들러의_줄.list)
				.as("업무 예외의 WARN(AU002)이 아니라 마지막 그물의 ERROR 다")
				.singleElement()
				.satisfies(event -> {
					assertThat(event.getLevel()).isEqualTo(Level.ERROR);
					assertThat(event.getFormattedMessage()).isEqualTo("unhandled exception");
					assertThat(((ThrowableProxy) event.getThrowableProxy()).getThrowable())
							.as("다시 던진 그 위반을 남긴다").isSameAs(violation);
				});
	}

	/**
	 * 검증 표 <b>「{@code uk_account_token_hash} 의 중복 INSERT → 그 로거의 ERROR 1」</b>. 잡지 않는 제약의 위반은 그대로 ERROR 다
	 * — 필터를 「중복 키 위반 문면 전부」 로 넓힌 변이를 이 줄이 잡는다.
	 */
	@Test
	@DisplayName("다른 UNIQUE 제약(uk_account_token_hash)의 위반은 그 로거의 ERROR 로 남는다")
	void 다른_UNIQUE_제약의_위반은_ERROR_로_남는다() {
		Long accountId = 계정을_넣는다("au25-token-hash@example.com");
		String 같은_해시 = AccountTokens.hash(AccountTokens.generate());
		this.accountTokenRepository.saveAndFlush(토큰(accountId, 같은_해시));

		assertThatThrownBy(() -> this.accountTokenRepository.saveAndFlush(토큰(accountId, 같은_해시)))
				.isInstanceOf(DataIntegrityViolationException.class);

		assertThat(수준별(Level.ERROR)).as("잡지 않는 제약의 위반은 ERROR 로 남는다 (§8.1)")
				.singleElement(STRING)
				.containsIgnoringCase("uk_account_token_hash");
		assertThat(수준별(Level.WARN)).containsExactly(H2_UNIQUE_WARN);
	}

	/**
	 * 검증 표 <b>「{@code fk_account_token_account} 의 위반 → 그 로거의 ERROR 1」</b>. Hibernate 를 거쳐 낸다 — 없는 계정을 참조해
	 * {@code saveAndFlush}. {@code JdbcTemplate} 은 {@code SqlExceptionHelper} 를 지나지 않는다. 필터를 「그 로거의 ERROR 전부」 로
	 * 넓힌 변이를 이 줄이 잡는다.
	 */
	@Test
	@DisplayName("FK 위반(fk_account_token_account)은 그 로거의 ERROR 로 남는다")
	void FK_위반은_ERROR_로_남는다() {
		long 없는_계정 = 9_000_002_505L;

		assertThatThrownBy(() -> this.accountTokenRepository.saveAndFlush(
				토큰(없는_계정, AccountTokens.hash(AccountTokens.generate()))))
				.isInstanceOf(DataIntegrityViolationException.class);

		assertThat(수준별(Level.ERROR)).as("다른 SQL 오류는 ERROR 로 남는다 (§8.1)")
				.singleElement(STRING)
				.containsIgnoringCase("fk_account_token_account");
		assertThat(수준별(Level.WARN)).as("WARN 줄도 그대로다").containsExactly(H2_FK_WARN);
	}

	/**
	 * 검증 표 <b>「루트 logger 의 appender → 콘솔만」</b>. Boot 의 기본 출력을 바꾸지 않는다 — {@code base.xml} 을 포함하면 파일
	 * appender 가 함께 달린다 (sp-docs/tech-stack.md §4.8).
	 */
	@Test
	@DisplayName("루트 logger 에는 콘솔 appender 하나만 있고 수준은 INFO 다")
	void 루트에는_콘솔만_있다() {
		LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
		Logger root = context.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
		List<Appender<ILoggingEvent>> appenders = new ArrayList<>();
		for (Iterator<Appender<ILoggingEvent>> it = root.iteratorForAppenders(); it.hasNext();) {
			appenders.add(it.next());
		}

		assertThat(appenders).singleElement().isInstanceOf(ConsoleAppender.class);
		assertThat(root.getLevel()).isEqualTo(Level.INFO);
	}

	/**
	 * 검증 표 <b>「{@code logback-spring.xml} 의 내용 — {@code <springProfile>} 이 없다」</b> (sp-docs/tech-stack.md §4.8). 필터는
	 * 모든 프로파일에 같다. 프로파일마다 컨텍스트를 띄워 보는 테스트는 logback 의 초기화가 한 번뿐이라 실행 순서에 기댈 수 있어 파일을
	 * 읽어 본다. 대소문자를 가리지 않고 찾는다 — logback 은 요소 이름을 대소문자 없이 맞춘다(logback-core 의 {@code ElementSelector}
	 * 읽기).
	 */
	@Test
	@DisplayName("logback-spring.xml 은 springProfile 로 가르지 않는다")
	void 설정_파일은_프로파일로_가르지_않는다() throws IOException {
		ClassPathResource file = new ClassPathResource("logback-spring.xml");

		assertThat(file.exists()).as("Boot 가 읽는 자리에 설정 파일이 있다").isTrue();
		assertThat(file.getContentAsString(StandardCharsets.UTF_8)).doesNotContainIgnoringCase("<springProfile");
	}

	// --- 도우미 ---

	private ResultActions 가입한다(String email) throws Exception {
		return this.mockMvc.perform(post("/api/v1/accounts")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content("{\"email\": \"" + email + "\", \"password\": \"" + RAW_PASSWORD + "\"}"));
	}

	/** 그 로거가 이 테스트의 스레드에서 남긴, 그 수준의 줄. */
	private List<String> 수준별(Level level) {
		String thread = Thread.currentThread().getName();
		return this.받은_줄.list.stream()
				.filter(event -> thread.equals(event.getThreadName()))
				.filter(event -> event.getLevel() == level)
				.map(ILoggingEvent::getFormattedMessage)
				.toList();
	}

	/** 줄의 문면과, 예외가 실렸으면 그 원인 사슬의 메시지. */
	private static String 줄의_전부(ILoggingEvent event) {
		StringBuilder text = new StringBuilder(event.getFormattedMessage());
		for (IThrowableProxy proxy = event.getThrowableProxy(); proxy != null; proxy = proxy.getCause()) {
			text.append('\n').append(proxy.getClassName()).append(": ").append(proxy.getMessage());
		}
		return text.toString();
	}

	private Long 계정을_넣는다(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				// 해시가 아니다. 이 행으로 로그인하지 않는다 (sp-docs/requirements/member.md §10.2)
				.password("test-not-a-hash-au25")
				.build()).getId();
	}

	private AccountToken 토큰(Long accountId, String tokenHash) {
		return AccountToken.issue(accountId, TokenPurpose.EMAIL_VERIFICATION, tokenHash, Duration.ofHours(24),
				this.clock);
	}

	/**
	 * 같은 이메일의 계정 행을 <b>다른 스레드에서</b> 커밋한다 — 다른 요청이 먼저 선점한 것과 같다. 부르는 스레드에는 가입
	 * 트랜잭션이 묶여 있어 같은 스레드의 {@code JdbcTemplate} 은 그 트랜잭션에 참여한다.
	 */
	private int 다른_스레드에서_같은_이메일로_넣는다(String email) {
		LocalDateTime now = LocalDateTime.now(this.clock).truncatedTo(ChronoUnit.SECONDS);
		ExecutorService 다른_스레드 = Executors.newSingleThreadExecutor();
		try {
			return 다른_스레드.submit(() -> this.jdbcTemplate.update(
					"insert into account (email, password, created_at, updated_at) values (?, ?, ?, ?)",
					email, "test-not-a-hash-au25", now, now)).get(10, TimeUnit.SECONDS);
		} catch (Exception e) {
			throw new IllegalStateException("끼운 행이 커밋되지 않았다 — 이 측정은 충돌을 볼 수 없다", e);
		} finally {
			다른_스레드.shutdownNow();
		}
	}

}
