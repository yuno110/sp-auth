package com.example.auth.global.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.service.AccountTokenIssuer;
import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.global.config.MailExecutorConfig;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.InMemoryMailer;
import com.example.auth.support.MailExecutorDrain;
import com.example.auth.support.MutableClock;
import com.example.auth.support.TestRsaKeys;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * 요청 수 제한을 실제 경로로 본다 — 인가·CORS 필터, 인터셉터, 컨트롤러, 예외 변환을 다 지난다 (sp-docs/security.md §10,
 * sp-docs/plan/phase2-auth-member.md AU-19 의 검증 표). 로그인은 {@code AuthController}, 나머지는 {@code AccountController} 의
 * 경로다.
 *
 * <p><b>한도를 작게 다시 덮은 컨텍스트를 따로 띄운다.</b> 테스트 프로파일은 한도를 크게 덮는다 — 다른 테스트들이 캐시된 컨텍스트의
 * 제한기 하나와 요청 주소 하나를 나눠 쓰기 때문이다({@code application-test.yml}). IP 키의 규칙끼리, 이메일 키의 규칙끼리 한도를
 * 다르게 두어 한 경로가 다른 규칙으로 세면 그 경로의 경계가 어긋난다. 창은 {@code application.yml} 의 정본 값이다.
 *
 * <p><b>테스트마다 다른 날의 창에서 센다.</b> 창이 바뀌면 배열이 비므로 앞선 테스트가 센 것이 남지 않는다. 다른 키가 같은 버킷에
 * 떨어지면 한도를 나누므로(sp-docs/security.md §10) 한도에 닿게 하는 규칙에는 한 창에서 그 키 하나만 보낸다. 같은 창에서 다른
 * 규칙에 보내는 키들은 모두 한 버킷에 떨어져도 그 규칙의 한도에 닿지 않을 만큼만 보낸다. 그래서 서로 다른 키가 따로 세지는 것은
 * 버킷을 직접 고르는 {@code RateLimiterTest} 가 보고, 여기서는 같은 키로 세지는 것을 본다. 다른 버킷의 키가 있어야 하는
 * 테스트는 이 컨텍스트의 제한기로 그 주소를 고른다.
 *
 * <p>MockMvc 는 Tomcat 의 주소 처리를 거치지 않는다 — 실서버의 동작은 통합 계획이 I 항목으로 세울 측정 대상이다
 * (sp-docs/plan/phase2-auth-member.md §5.1).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
		"rate-limit.rules.check-email.limit=" + RateLimitControllerTest.CHECK_EMAIL_LIMIT,
		"rate-limit.rules.signup.limit=" + RateLimitControllerTest.SIGNUP_LIMIT,
		"rate-limit.rules.password-reset-ip.limit=" + RateLimitControllerTest.PASSWORD_RESET_IP_LIMIT,
		"rate-limit.rules.password-reset-email.limit=" + RateLimitControllerTest.PASSWORD_RESET_EMAIL_LIMIT,
		"rate-limit.rules.verification-ip.limit=" + RateLimitControllerTest.VERIFICATION_IP_LIMIT,
		"rate-limit.rules.verification-email.limit=" + RateLimitControllerTest.VERIFICATION_EMAIL_LIMIT,
		"rate-limit.rules.login.limit=" + RateLimitControllerTest.LOGIN_LIMIT
})
class RateLimitControllerTest {

	static final int CHECK_EMAIL_LIMIT = 3;

	static final int SIGNUP_LIMIT = 2;

	static final int PASSWORD_RESET_IP_LIMIT = 4;

	static final int PASSWORD_RESET_EMAIL_LIMIT = 2;

	static final int VERIFICATION_IP_LIMIT = 5;

	static final int VERIFICATION_EMAIL_LIMIT = 3;

	static final int LOGIN_LIMIT = 6;

	/** 이 클래스가 덮은 한도 중 가장 큰 것보다 하나 많다. 제한하지 않는 요청을 이만큼 보내도 429 가 아니다. */
	private static final int MORE_THAN_ANY_LIMIT = IntStream.of(CHECK_EMAIL_LIMIT, SIGNUP_LIMIT, PASSWORD_RESET_IP_LIMIT,
			PASSWORD_RESET_EMAIL_LIMIT, VERIFICATION_IP_LIMIT, VERIFICATION_EMAIL_LIMIT, LOGIN_LIMIT).max().orElseThrow() + 1;

	/** {@code application-test.yml} 의 허용 오리진. */
	private static final String ALLOWED_ORIGIN = "http://localhost:3000";

	private static final String RAW_PASSWORD = "Passw0rd!";

	private static final String WRONG_PASSWORD = "Other1!pw";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 정리가 남긴다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	/** sp-docs/api-contract.md §9.13 의 본문. */
	private static final String TOO_MANY_REQUESTS_BODY = "{\"success\":false,\"data\":null,\"error\":{\"code\":\"C009\","
			+ "\"message\":\"요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.\",\"fieldErrors\":[]}}";

	/** 재발송·재설정 요청의 202 본문 (sp-docs/api-contract.md §2.4). */
	private static final String ACCEPTED_BODY = "{\"success\":true,\"data\":null,\"error\":null}";

	private static final MutableClock CLOCK = new MutableClock();

	/** 테스트마다 다음 날을 쓴다. */
	private static final AtomicInteger DAYS = new AtomicInteger();

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	/** 애플리케이션의 {@code Clock} 빈을 {@link #CLOCK} 로 바꾼다 — 제한기가 이 시계로 창을 정한다. */
	@TestBean
	private Clock clock;

	static Clock clock() {
		return CLOCK;
	}

	/** 재발송·재설정 요청이 발급 작업을 넘기는지 센다. 나머지는 실제 빈에 위임된다. */
	@MockitoSpyBean
	private AccountTokenIssuer accountTokenIssuer;

	/** 로그인의 비밀번호 비교를 센다. 나머지는 실제 빈에 위임된다 — 픽스처의 인코딩도 실제 빈이 한다. */
	@MockitoSpyBean
	private PasswordEncoder passwordEncoder;

	@Autowired
	private MockMvc mockMvc;

	/** 이 컨텍스트의 제한기 — 다른 버킷에 떨어지는 주소를 고를 때 쓴다. 버킷을 고르는 비밀이 이 제한기의 것이다. */
	@Autowired
	private RateLimiter rateLimiter;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private InMemoryMailer inMemoryMailer;

	@Autowired
	@Qualifier(MailExecutorConfig.ISSUE_EXECUTOR)
	private ThreadPoolTaskExecutor issueExecutor;

	@Autowired
	@Qualifier(MailExecutorConfig.SEND_EXECUTOR)
	private ThreadPoolTaskExecutor sendExecutor;

	/** 이 테스트가 쓰는 날. 창은 이 날의 시각으로 정한다. */
	private LocalDate today;

	@BeforeEach
	void 이_테스트의_날을_고른다() {
		this.today = LocalDate.of(2031, 1, 1).plusDays(DAYS.getAndIncrement());
		시각("10:00");
	}

	/**
	 * 발급 작업이 끝나기를 기다린 뒤 만든 행을 지운다 — 남기면 계정 삭제가 {@code fk_account_token_account} 에 걸린다. H2 는
	 * 테스트 클래스 사이에 공유되므로({@code DB_CLOSE_DELAY=-1}) seed 계정은 남긴다.
	 */
	@AfterEach
	void 정리() {
		CLOCK.reset();
		MailExecutorDrain.drain(this.issueExecutor, this.sendExecutor);
		this.inMemoryMailer.clear();
		this.jdbcTemplate.update("delete from account_token");
		this.jdbcTemplate.update("delete from login_attempt");
		this.jdbcTemplate.update("delete from refresh_token");
		this.jdbcTemplate.update("delete from account where email <> ?", ADMIN_EMAIL);
	}

	// --- IP 키 ---

	/** 성공한 요청(200)과 실패한 요청(400)을 섞어 보낸다 — 그 경로에 닿은 요청은 응답과 상관없이 센다. */
	@Test
	@DisplayName("check-email 을 한도까지 보내면 통과하고 다음이 429 C009 + Retry-After 다 — 성공·실패를 가리지 않고 센다")
	void check_email_을_한도까지_한_번_더() throws Exception {
		for (int i = 0; i < CHECK_EMAIL_LIMIT; i++) {
			if (i % 2 == 0) {
				this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.10")).andExpect(status().isOk());
			} else {
				this.mockMvc.perform(중복_확인("not-an-email", "203.0.113.10")).andExpect(status().isBadRequest());
			}
		}

		MockHttpServletResponse response =
				this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.10")).andReturn().getResponse();

		assertThat(response.getStatus()).isEqualTo(429);
		assertThat(response.getContentAsString(StandardCharsets.UTF_8)).isEqualTo(TOO_MANY_REQUESTS_BODY);
		assertThat(response.getHeader(HttpHeaders.RETRY_AFTER)).as("10:00:00 에 넘었다 — 분 창의 끝까지 60초").isEqualTo("60");
	}

	/**
	 * 창이 바뀐 뒤의 첫 요청은 다른 버킷에 떨어지는 주소에서 보낸다. 배열은 창이 바뀐 뒤 그 규칙의 첫 요청이 비우므로, 한도를 채운
	 * 주소가 그 첫 요청이면 그 요청의 버킷만 비우는 구현도 통과한다.
	 */
	@Test
	@DisplayName("시계를 창 경계 너머로 옮기면 다른 주소가 먼저 와도 다시 통과한다 — 경계 1ns 전까지는 429 다")
	void 창_경계를_넘으면_다시_통과한다() throws Exception {
		String other = 다른_버킷의_주소("203.0.113.11");
		한도까지_보낸다(() -> 중복_확인("au19-free@example.com", "203.0.113.11"), CHECK_EMAIL_LIMIT);

		시각("10:00:59.999999999");
		this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.11"))
				.andExpect(status().isTooManyRequests())
				.andExpect(header().string(HttpHeaders.RETRY_AFTER, "1"));

		시각("10:01");
		this.mockMvc.perform(중복_확인("au19-free@example.com", other)).andExpect(status().isOk());
		this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.11")).andExpect(status().isOk());
	}

	@Test
	@DisplayName("Retry-After 는 창 끝까지 남은 초의 올림이다 — 10:00:20.4 에 넘으면 39.6초가 남아 40")
	void Retry_After_는_남은_초의_올림이다() throws Exception {
		시각("10:00:20.4");
		한도까지_보낸다(() -> 중복_확인("au19-free@example.com", "203.0.113.12"), CHECK_EMAIL_LIMIT);

		this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.12"))
				.andExpect(status().isTooManyRequests())
				.andExpect(header().string(HttpHeaders.RETRY_AFTER, "40"));
	}

	static Stream<Arguments> IP_규칙() {
		return Stream.of(
				Arguments.of("GET /api/v1/accounts/check-email", (Supplier<MockHttpServletRequestBuilder>)
						() -> get("/api/v1/accounts/check-email").param("email", "not-an-email"), CHECK_EMAIL_LIMIT, "60"),
				Arguments.of("POST /api/v1/accounts", (Supplier<MockHttpServletRequestBuilder>)
						() -> json(post("/api/v1/accounts"), "{}"), SIGNUP_LIMIT, "3600"),
				Arguments.of("POST /api/v1/accounts/password-reset", (Supplier<MockHttpServletRequestBuilder>)
						() -> json(post("/api/v1/accounts/password-reset"), "{}"), PASSWORD_RESET_IP_LIMIT, "3600"),
				Arguments.of("POST /api/v1/accounts/email-verification", (Supplier<MockHttpServletRequestBuilder>)
						() -> json(post("/api/v1/accounts/email-verification"), "{}"), VERIFICATION_IP_LIMIT, "3600"),
				Arguments.of("POST /api/v1/auth/login", (Supplier<MockHttpServletRequestBuilder>)
						() -> json(post("/api/v1/auth/login"), "{}"), LOGIN_LIMIT, "60"));
	}

	/**
	 * 표의 경로마다 그 규칙의 한도·창으로 센다 (sp-docs/security.md §10). 본문이 틀린 요청(400·401)으로 센다 — 검증보다 앞에서
	 * 세므로 그 요청도 한도를 쓴다. Retry-After 가 그 규칙의 창 길이다 — 10:00:00 에 넘었다.
	 */
	@ParameterizedTest(name = "{0}")
	@MethodSource("IP_규칙")
	@DisplayName("표의 경로마다 그 규칙의 한도에서 429 이고 Retry-After 가 그 규칙의 창이다")
	void 표의_경로마다_그_규칙으로_센다(String name, Supplier<MockHttpServletRequestBuilder> request, int limit,
			String retryAfter) throws Exception {
		한도까지_보낸다(() -> request.get().with(주소("203.0.113.13")), limit);

		this.mockMvc.perform(request.get().with(주소("203.0.113.13")))
				.andExpect(status().isTooManyRequests())
				.andExpect(jsonPath("$.error.code").value("C009"))
				.andExpect(header().string(HttpHeaders.RETRY_AFTER, retryAfter));
	}

	/** 클라이언트가 임의로 쓰는 헤더라 믿으면 요청마다 주소를 바꿔 제한을 비켜 간다 (sp-docs/security.md §10). */
	@Test
	@DisplayName("요청마다 다른 X-Forwarded-For·X-Real-IP 를 실어도 remoteAddr 하나로 센다")
	void 전달_헤더가_달라도_같은_키로_센다() throws Exception {
		for (int i = 0; i < CHECK_EMAIL_LIMIT; i++) {
			this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.14")
							.header("X-Forwarded-For", "198.51.100." + i)
							.header("X-Real-IP", "198.51.100." + i))
					.andExpect(status().isOk());
		}

		this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.14")
						.header("X-Forwarded-For", "198.51.100.200")
						.header("X-Real-IP", "198.51.100.200"))
				.andExpect(status().isTooManyRequests());
	}

	@Test
	@DisplayName("같은 IPv6 /64 의 서로 다른 주소들은 한 키로 센다")
	void 같은_64_의_IPv6_는_한_키다() throws Exception {
		List<String> addresses = List.of("2001:db8:19:1::1", "2001:db8:19:1:ffff:ffff:ffff:fffe",
				"2001:db8:19:1:1234:5678:9abc:def0", "2001:db8:19:1::abcd");

		for (int i = 0; i < CHECK_EMAIL_LIMIT; i++) {
			this.mockMvc.perform(중복_확인("au19-free@example.com", addresses.get(i))).andExpect(status().isOk());
		}
		this.mockMvc.perform(중복_확인("au19-free@example.com", addresses.get(CHECK_EMAIL_LIMIT)))
				.andExpect(status().isTooManyRequests());
	}

	@Test
	@DisplayName("IPv4 사상 주소(::ffff:a.b.c.d)와 그 IPv4 주소는 한 키로 센다")
	void IPv4_사상_주소는_IPv4_와_한_키다() throws Exception {
		for (int i = 0; i < CHECK_EMAIL_LIMIT; i++) {
			String address = (i % 2 == 0) ? "::ffff:203.0.113.15" : "203.0.113.15";
			this.mockMvc.perform(중복_확인("au19-free@example.com", address)).andExpect(status().isOk());
		}
		String last = (CHECK_EMAIL_LIMIT % 2 == 0) ? "::ffff:203.0.113.15" : "203.0.113.15";
		this.mockMvc.perform(중복_확인("au19-free@example.com", last)).andExpect(status().isTooManyRequests());
	}

	/** preflight 는 CORS 필터가 답하고 끝낸다. 세면 브라우저의 요청 하나가 둘로 세진다. */
	@Test
	@DisplayName("preflight(OPTIONS)는 세지 않는다 — 한도보다 많이 보낸 뒤에도 실제 요청이 한도까지 통과한다")
	void preflight_는_세지_않는다() throws Exception {
		for (int i = 0; i < CHECK_EMAIL_LIMIT + 2; i++) {
			this.mockMvc.perform(options("/api/v1/accounts/check-email")
							.header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
							.header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
							.with(주소("203.0.113.16")))
					.andExpect(status().isOk());
		}

		한도까지_보낸다(() -> 중복_확인("au19-free@example.com", "203.0.113.16"), CHECK_EMAIL_LIMIT);
		this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.16")).andExpect(status().isTooManyRequests());
	}

	/**
	 * HEAD 는 같은 경로의 GET 핸들러가 받으므로 GET 의 규칙으로 센다({@link RateLimitRule#ipRuleOf}). HEAD 로 한도를 채우면 같은
	 * 주소의 GET 이 넘고, 한도를 넘은 HEAD 도 429 다. check-email 의 HEAD 는 무인증으로 열린 요청이 아니라(SecurityConfig) 토큰을
	 * 싣는다.
	 */
	@Test
	@DisplayName("HEAD 는 같은 경로의 GET 과 한 IP 키로 센다 — HEAD 로 한도를 채우면 GET 이 429 이고, 한도를 넘은 HEAD 도 429 다")
	void HEAD_는_GET_과_한_키로_센다() throws Exception {
		Long accountId = 계정을_만든다("au19-head@example.com");
		String accessToken = this.jwtTokenProvider.issue(accountId, Role.USER).accessToken();
		for (int i = 0; i < CHECK_EMAIL_LIMIT; i++) {
			this.mockMvc.perform(중복_확인_HEAD("203.0.113.22", accessToken)).andExpect(status().isOk());
		}

		this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.22")).andExpect(status().isTooManyRequests());
		this.mockMvc.perform(중복_확인_HEAD("203.0.113.22", accessToken))
				.andExpect(status().isTooManyRequests())
				.andExpect(header().string(HttpHeaders.RETRY_AFTER, "60"));
	}

	/**
	 * 응답이 CORS 처리보다 앞에서 끝나면 브라우저는 429 를 보지 못하고 CORS 실패를 본다 (sp-docs/security.md §10). 노출 헤더가
	 * 없으면 스크립트가 Retry-After 를 읽지 못한다 (sp-docs/security.md §1.1).
	 */
	@Test
	@DisplayName("IP 키의 429 에 Access-Control-Allow-Origin 이 있고 Retry-After 가 노출된다")
	void IP_키의_429_에_CORS_헤더가_실린다() throws Exception {
		for (int i = 0; i < CHECK_EMAIL_LIMIT; i++) {
			this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.17").header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN))
					.andExpect(status().isOk());
		}

		this.mockMvc.perform(중복_확인("au19-free@example.com", "203.0.113.17").header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN))
				.andExpect(status().isTooManyRequests())
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED_ORIGIN))
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.RETRY_AFTER))
				.andExpect(header().exists(HttpHeaders.RETRY_AFTER));
	}

	/**
	 * IP 키를 넘은 로그인은 핸들러에 닿지 않는다 (sp-docs/security.md §10) — 비밀번호 비교(BCrypt)도 잠금 카운터도 돌지 않는다.
	 * 첫 실패는 한도 안이라 세진다. 그것이 대조군이다.
	 */
	@Test
	@DisplayName("로그인 — IP 키를 넘은 요청은 비밀번호를 비교하지 않고 실패 카운터를 세지 않는다. 맞는 비밀번호도 429 다")
	void 로그인_한도를_넘은_요청은_비교도_세기도_하지_않는다() throws Exception {
		String email = "au19-login@example.com";
		Long accountId = 계정을_만든다(email);
		this.mockMvc.perform(로그인(email, WRONG_PASSWORD).with(주소("203.0.113.18")))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU003"));
		assertThat(실패_수(email)).as("한도 안의 실패는 세진다").isEqualTo(1);
		한도까지_보낸다(() -> json(post("/api/v1/auth/login"), "{}").with(주소("203.0.113.18")), LOGIN_LIMIT - 1);
		clearInvocations(this.passwordEncoder);

		this.mockMvc.perform(로그인(email, WRONG_PASSWORD).with(주소("203.0.113.18")))
				.andExpect(status().isTooManyRequests())
				.andExpect(jsonPath("$.error.code").value("C009"));
		this.mockMvc.perform(로그인(email, RAW_PASSWORD).with(주소("203.0.113.18")))
				.andExpect(status().isTooManyRequests())
				.andExpect(jsonPath("$.error.code").value("C009"));

		verify(this.passwordEncoder, never()).matches(any(), any());
		assertThat(실패_수(email)).as("429 는 실패 카운터를 세지 않는다").isEqualTo(1);
		assertThat(this.jdbcTemplate.queryForObject(
				"select count(*) from refresh_token where account_id = ?", Integer.class, accountId))
				.as("맞는 비밀번호도 토큰을 받지 못한다").isZero();
	}

	/**
	 * 규칙은 요청 URI 의 글자가 아니라 요청이 닿은 핸들러의 경로로 고른다. 퍼센트 인코딩한 글자({@code %6C} = {@code l})로
	 * 로그인 경로에 닿은 요청도 로그인으로 센다.
	 */
	@Test
	@DisplayName("퍼센트 인코딩한 경로로 로그인에 닿은 요청도 로그인 한도로 센다")
	void 인코딩한_경로도_같은_규칙으로_센다() throws Exception {
		for (int i = 0; i < LOGIN_LIMIT; i++) {
			this.mockMvc.perform(json(post(URI.create("/api/v1/auth/%6Cogin")), "{}").with(주소("203.0.113.19")))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.error.code").value("AU003"));
		}

		this.mockMvc.perform(json(post("/api/v1/auth/login"), "{}").with(주소("203.0.113.19")))
				.andExpect(status().isTooManyRequests());
	}

	/** 확인({@code …/confirm})은 토큰이 256비트 무작위라 제한하지 않는다. 재발급도 표에 없다 (sp-docs/security.md §10). */
	@ParameterizedTest(name = "{0}")
	@MethodSource("제한하지_않는_요청")
	@DisplayName("확인·재발급은 몇 번이든 429 가 아니다")
	void 확인과_재발급은_429_가_아니다(String name, Supplier<MockHttpServletRequestBuilder> request) throws Exception {
		for (int i = 0; i < MORE_THAN_ANY_LIMIT; i++) {
			int status = this.mockMvc.perform(request.get().with(주소("203.0.113.20"))).andReturn().getResponse().getStatus();
			assertThat(status).as("%d 번째", i + 1).isNotEqualTo(429);
		}
	}

	static Stream<Arguments> 제한하지_않는_요청() {
		return Stream.of(
				Arguments.of("POST /api/v1/accounts/email-verification/confirm", (Supplier<MockHttpServletRequestBuilder>)
						() -> json(post("/api/v1/accounts/email-verification/confirm"), "{\"token\": \"au19-unknown\"}")),
				Arguments.of("POST /api/v1/accounts/password-reset/confirm", (Supplier<MockHttpServletRequestBuilder>)
						() -> json(post("/api/v1/accounts/password-reset/confirm"),
								"{\"token\": \"au19-unknown\", \"newPassword\": \"NewPassw0rd!\"}")),
				Arguments.of("POST /api/v1/auth/reissue", (Supplier<MockHttpServletRequestBuilder>)
						() -> json(post("/api/v1/auth/reissue"), "{\"refreshToken\": \"au19-unknown\"}")));
	}

	/** 인증된 요청은 토큰이 신원을 묶어 제한하지 않는다 (sp-docs/security.md §10). */
	@Test
	@DisplayName("표에 없는 요청(GET /api/v1/accounts/me)은 몇 번이든 429 가 아니다")
	void 표에_없는_요청은_429_가_아니다() throws Exception {
		Long accountId = 계정을_만든다("au19-me@example.com");
		String accessToken = this.jwtTokenProvider.issue(accountId, Role.USER).accessToken();

		for (int i = 0; i < MORE_THAN_ANY_LIMIT; i++) {
			this.mockMvc.perform(get("/api/v1/accounts/me")
							.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
							.with(주소("203.0.113.21")))
					.andExpect(status().isOk());
		}
	}

	// --- 이메일 키 — 재발송·재설정 요청 ---

	/** 재발송·재설정 요청. 이메일 키의 규칙·발급 작업의 목적이 저마다 다르다. */
	enum 메일_요청 {

		재설정("/api/v1/accounts/password-reset", TokenPurpose.PASSWORD_RESET, PASSWORD_RESET_EMAIL_LIMIT),
		재발송("/api/v1/accounts/email-verification", TokenPurpose.EMAIL_VERIFICATION, VERIFICATION_EMAIL_LIMIT);

		private final String path;

		private final TokenPurpose purpose;

		private final int emailLimit;

		메일_요청(String path, TokenPurpose purpose, int emailLimit) {
			this.path = path;
			this.purpose = purpose;
			this.emailLimit = emailLimit;
		}

	}

	/**
	 * 같은 이메일을 요청마다 다른 주소에서 보낸다 — IP 키는 주소마다 한 번이라 한도에 닿지 않는다. 이메일 키의 한도를 넘은 요청은
	 * 발급 작업을 넘기지 않는다 (sp-docs/security.md §10).
	 */
	@ParameterizedTest(name = "{0}")
	@EnumSource(메일_요청.class)
	@DisplayName("같은 이메일을 다른 주소에서 보내면 이메일 키의 한도에서 429 이고, 넘은 요청은 발급 작업을 넘기지 않는다")
	void 같은_이메일은_이메일_키의_한도에서_429(메일_요청 request) throws Exception {
		String email = "au19-same-" + request.name() + "@example.com";
		for (int i = 0; i < request.emailLimit; i++) {
			this.mockMvc.perform(메일(request, email, "198.51.100." + (10 + i))).andExpect(status().isAccepted());
		}

		this.mockMvc.perform(메일(request, email, "198.51.100.99"))
				.andExpect(status().isTooManyRequests())
				.andExpect(jsonPath("$.error.code").value("C009"));

		verify(this.accountTokenIssuer, times(request.emailLimit)).request(eq(request.purpose), anyString());
	}

	/**
	 * 이메일 키는 {@code Locale.ROOT} 소문자다 (sp-docs/security.md §10). 로그인 잠금의 키처럼 ASCII 만 바꾸면 {@code Ä} 와
	 * {@code ä} 가 다른 키가 되어 한도에 닿지 않는다. 비ASCII 로컬 파트는 검증을 지난다 (sp-docs/requirements/member.md §2.0).
	 */
	@ParameterizedTest(name = "{0}")
	@EnumSource(메일_요청.class)
	@DisplayName("비ASCII 대문자를 포함한 대소문자 변형을 다른 주소에서 보내도 한 이메일 키로 센다")
	void 대소문자_변형은_한_이메일_키다(메일_요청 request) throws Exception {
		List<String> variants = List.of("Äbc.Au19@Example.com", "äbc.au19@example.com", "ÄBC.AU19@EXAMPLE.COM",
				"äBc.aU19@eXample.com");
		for (int i = 0; i < request.emailLimit; i++) {
			this.mockMvc.perform(메일(request, variants.get(i), "198.51.100." + (20 + i))).andExpect(status().isAccepted());
		}

		this.mockMvc.perform(메일(request, variants.get(request.emailLimit), "198.51.100.98"))
				.andExpect(status().isTooManyRequests());
	}

	/**
	 * 소문자는 JVM 의 기본 로캘을 따르지 않는다 — {@code Locale.ROOT} 다 (sp-docs/security.md §10). 기본 로캘을 따르면 터키어
	 * 로캘에서 {@code I} 가 점 없는 {@code ı} 가 되어 {@code I} 와 {@code i} 가 다른 키로 세진다. 기본 로캘은 이 테스트 안에서만
	 * 바꾸고 되돌린다.
	 */
	@ParameterizedTest(name = "{0}")
	@EnumSource(메일_요청.class)
	@DisplayName("기본 로캘이 터키어여도 I 와 i 를 한 이메일 키로 센다")
	void 기본_로캘과_상관없이_한_이메일_키다(메일_요청 request) throws Exception {
		Locale original = Locale.getDefault();
		Locale.setDefault(Locale.forLanguageTag("tr-TR"));
		try {
			for (int i = 0; i < request.emailLimit; i++) {
				String email = (i % 2 == 0) ? "Iris.au19@example.com" : "iris.au19@example.com";
				this.mockMvc.perform(메일(request, email, "198.51.100." + (80 + i))).andExpect(status().isAccepted());
			}

			this.mockMvc.perform(메일(request, "IRIS.AU19@example.com", "198.51.100.89"))
					.andExpect(status().isTooManyRequests());
		} finally {
			Locale.setDefault(original);
		}
	}

	/**
	 * 검증에 실패한 요청은 이메일 키로 세지 않는다 — IP 키로는 센다 (sp-docs/security.md §10). 같은 형식 위반을 이메일 한도보다
	 * 많이 보내도 400 이다. 한 주소에서 IP 한도만큼 보낸 형식 위반은 그 주소의 다음 요청을 429 로 만든다 — 키가 섞이지 않게 다음
	 * 시의 창에서 본다.
	 */
	@Test
	@DisplayName("재설정 요청의 형식 위반은 400 C001 이고 이메일 키로 세지 않는다. IP 키로는 센다")
	void 형식_위반은_이메일_키로_세지_않는다() throws Exception {
		for (int i = 0; i <= PASSWORD_RESET_EMAIL_LIMIT; i++) {
			this.mockMvc.perform(메일(메일_요청.재설정, "not-an-email", "198.51.100." + (30 + i)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.error.code").value("C001"));
		}

		시각("11:00");
		한도까지_보낸다(() -> 메일(메일_요청.재설정, "not-an-email", "198.51.100.40"), PASSWORD_RESET_IP_LIMIT);
		this.mockMvc.perform(메일(메일_요청.재설정, "au19-valid@example.com", "198.51.100.40"))
				.andExpect(status().isTooManyRequests());

		verify(this.accountTokenIssuer, never()).request(any(), any());
	}

	/**
	 * 429 도 계정의 상태를 말하지 않는다 — 이메일 키는 계정을 찾지 않고 요청의 이메일로만 정한다 (sp-docs/security.md §4.1 §10).
	 * 있는 계정과 없는 이메일을 같은 순서로 보내 응답(상태·본문·Retry-After)을 견준다. 둘을 다른 시의 같은 분에서 보낸다 — 키가
	 * 섞이지 않고 Retry-After 가 같다.
	 */
	@ParameterizedTest(name = "{0}")
	@EnumSource(메일_요청.class)
	@DisplayName("이메일 키의 429 까지의 응답이 계정이 있든 없든 같다")
	void 이메일_키의_응답은_계정의_유무로_갈리지_않는다(메일_요청 request) throws Exception {
		계정을_만든다("au19-exists@example.com");

		시각("10:20");
		List<String> exists = 한도_너머까지의_응답(request, "au19-exists@example.com", 50);
		시각("11:20");
		List<String> missing = 한도_너머까지의_응답(request, "au19-missing@example.com", 60);

		assertThat(exists).as("한도까지 202, 다음이 429").hasSize(request.emailLimit + 1);
		assertThat(exists.subList(0, request.emailLimit)).containsOnly("202 " + ACCEPTED_BODY + " null");
		assertThat(exists.get(request.emailLimit)).isEqualTo("429 " + TOO_MANY_REQUESTS_BODY + " 2400");
		assertThat(missing).isEqualTo(exists);
	}

	/** 이메일 키의 429 도 컨트롤러 안이라 CORS 처리 뒤다 (sp-docs/security.md §10). */
	@Test
	@DisplayName("이메일 키의 429 에도 Access-Control-Allow-Origin 이 있고 Retry-After 가 노출된다")
	void 이메일_키의_429_에_CORS_헤더가_실린다() throws Exception {
		for (int i = 0; i < PASSWORD_RESET_EMAIL_LIMIT; i++) {
			this.mockMvc.perform(메일(메일_요청.재설정, "au19-cors@example.com", "198.51.100." + (70 + i))
							.header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN))
					.andExpect(status().isAccepted());
		}

		this.mockMvc.perform(메일(메일_요청.재설정, "au19-cors@example.com", "198.51.100.79")
						.header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN))
				.andExpect(status().isTooManyRequests())
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED_ORIGIN))
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.RETRY_AFTER))
				.andExpect(header().exists(HttpHeaders.RETRY_AFTER));
	}

	/** 한도 + 1 번의 응답을 {@code "<상태> <본문> <Retry-After>"} 로 모은다. 요청마다 다른 주소다. */
	private List<String> 한도_너머까지의_응답(메일_요청 request, String email, int firstHost) throws Exception {
		List<String> responses = new ArrayList<>();
		for (int i = 0; i <= request.emailLimit; i++) {
			MockHttpServletResponse response = this.mockMvc.perform(
					메일(request, email, "198.51.100." + (firstHost + i))).andReturn().getResponse();
			responses.add(response.getStatus() + " " + response.getContentAsString(StandardCharsets.UTF_8) + " "
					+ response.getHeader(HttpHeaders.RETRY_AFTER));
		}
		return responses;
	}

	/** 한 키로 한도만큼 보낸다. 어느 것도 429 가 아니다. */
	private void 한도까지_보낸다(Supplier<MockHttpServletRequestBuilder> request, int limit) throws Exception {
		for (int i = 0; i < limit; i++) {
			int status = this.mockMvc.perform(request.get()).andReturn().getResponse().getStatus();
			assertThat(status).as("한도 안의 %d 번째", i + 1).isNotEqualTo(429);
		}
	}

	private void 시각(String time) {
		CLOCK.set(this.today.atTime(LocalTime.parse(time)));
	}

	/** 인증된 계정. 비밀번호는 런타임에 인코딩한다 — 해시를 테스트 파일에 적지 않는다 (sp-docs/requirements/member.md §10.2). */
	private Long 계정을_만든다(String email) {
		Account account = Account.builder().email(email).password(this.passwordEncoder.encode(RAW_PASSWORD)).build();
		account.markEmailVerified(CLOCK);
		return this.accountRepository.saveAndFlush(account).getId();
	}

	/** 커밋된 실패 수. 행이 없으면 0 이다. */
	private int 실패_수(String email) {
		return this.jdbcTemplate.queryForList("select failed_count from login_attempt where email_key = ?", Integer.class,
				LoginAttempt.emailKeyOf(email)).stream().findFirst().orElse(0);
	}

	private MockHttpServletRequestBuilder 중복_확인(String email, String remoteAddr) {
		return get("/api/v1/accounts/check-email").param("email", email).with(주소(remoteAddr));
	}

	/** 인증된 HEAD 의 중복 확인. 이메일은 형식이 맞는 값이다. */
	private static MockHttpServletRequestBuilder 중복_확인_HEAD(String remoteAddr, String accessToken) {
		return head("/api/v1/accounts/check-email").param("email", "au19-free@example.com")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
				.with(주소(remoteAddr));
	}

	/** 그 주소와 IP 키가 다른 버킷에 떨어지는 주소. 버킷은 이 컨텍스트의 제한기가 고른다 — 비밀이 그 제한기의 것이다. */
	private String 다른_버킷의_주소(String remoteAddr) {
		int bucket = this.rateLimiter.bucketOf(RateLimitInterceptor.ipKeyOf(remoteAddr));
		return IntStream.rangeClosed(1, 254).mapToObj(i -> "192.0.2." + i)
				.filter(candidate -> this.rateLimiter.bucketOf(RateLimitInterceptor.ipKeyOf(candidate)) != bucket)
				.findFirst()
				.orElseThrow(() -> new AssertionError("모든 주소가 한 버킷에 떨어진다 — 버킷을 키로 고르지 않는다"));
	}

	private static MockHttpServletRequestBuilder 로그인(String email, String password) {
		return json(post("/api/v1/auth/login"), "{\"email\": \"" + email + "\", \"password\": \"" + password + "\"}");
	}

	private static MockHttpServletRequestBuilder 메일(메일_요청 request, String email, String remoteAddr) {
		return json(post(request.path), "{\"email\": \"" + email + "\"}").with(주소(remoteAddr));
	}

	private static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder builder, String body) {
		return builder.contentType(MediaType.APPLICATION_JSON).characterEncoding(StandardCharsets.UTF_8).content(body);
	}

	/** 요청의 {@code remoteAddr}. MockMvc 의 기본값은 모든 요청이 같다. */
	private static RequestPostProcessor 주소(String remoteAddr) {
		return request -> {
			request.setRemoteAddr(remoteAddr);
			return request;
		};
	}

}
