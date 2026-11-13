package com.example.auth.global.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.support.AccountReader;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.global.security.SecurityErrorResponder;
import com.example.auth.support.TestRsaKeys;
import com.example.auth.support.TestTokens;
import com.example.securityprobe.CurrentAccountProbeController;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * sp-docs/plan/phase1.md §4 AU-04 의 "검증" 표 중 인가 쪽을 테스트로 옮긴 것이다. 이메일 인증·
 * 비밀번호 재설정·계정 목록의 경로, 무인증 경로에 실린 거부되는 토큰, CORS 의 노출 헤더는
 * sp-docs/plan/phase2-auth-member.md 의 AU-13 이 더했다.
 *
 * <p>업무 경로의 정본은 sp-docs/api-contract.md §2, 인프라 경로는 sp-docs/security.md §5.1.1 이다.
 *
 * <p><b>컨트롤러는 아직 없다</b>(AU-05~AU-10). 그래서 무인증 경로의 기대값을 "200"이 아니라
 * <b>"401 이 아님"</b>으로 둔다 — 인가를 통과하면 그 뒤는 매핑 없음(404)이 된다. 컨트롤러가
 * 생겨도 이 단언은 그대로 유효하다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityConfigTest {

	/** application-test.yml 이 주는 테스트 전용 오리진. */
	private static final String ALLOWED_ORIGIN = "http://localhost:3000";

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	/** 만료된 토큰 픽스처를 애플리케이션의 서명 키로 만든다 ({@link TestTokens}). */
	@Autowired
	private JwtEncoder jwtEncoder;

	@Autowired
	private CorsConfigurationSource corsConfigurationSource;

	@Autowired
	private SecurityErrorResponder securityErrorResponder;

	@Autowired
	private ApplicationContext applicationContext;

	// --- 업무 경로 (sp-docs/api-contract.md §2) ---

	@ParameterizedTest(name = "{0} {1}")
	@CsvSource({
			"GET,/api/v1/accounts/me",
			"PATCH,/api/v1/accounts/me/password",
			"DELETE,/api/v1/accounts/me",
			"POST,/api/v1/auth/logout",
			// 계정 목록 (sp-docs/api-contract.md §2.5). POST /accounts 의 permitAll 이 메서드를 붙인
			// 그대로여야 이 경로가 열리지 않는다 (§2.4 의 SecurityConfig 문단)
			"GET,/api/v1/accounts"
	})
	@DisplayName("인증이 필요한 경로는 토큰 없이 401 A001 이다")
	void 인증이_필요한_경로(String method, String path) throws Exception {
		this.mockMvc.perform(request(HttpMethod.valueOf(method), path))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("A001"))
				.andExpect(jsonPath("$.error.message").value("인증이 필요합니다."));
	}

	@ParameterizedTest(name = "{0} {1}")
	@CsvSource({
			"POST,/api/v1/accounts",
			"GET,/api/v1/accounts/check-email",
			"POST,/api/v1/auth/login",
			"POST,/api/v1/auth/reissue",
			// 이메일 인증과 비밀번호 재설정 (sp-docs/api-contract.md §2.4)
			"POST,/api/v1/accounts/email-verification",
			"POST,/api/v1/accounts/email-verification/confirm",
			"POST,/api/v1/accounts/password-reset",
			"POST,/api/v1/accounts/password-reset/confirm"
	})
	@DisplayName("무인증 경로는 토큰 없이도 401 이 아니다")
	void 무인증_경로(String method, String path) throws Exception {
		this.mockMvc.perform(request(HttpMethod.valueOf(method), path))
				.andExpect(notUnauthorized());
	}

	/**
	 * sp-docs/api-contract.md §2.4 의 경로는 메서드를 붙여 하나씩 열었다. 같은 경로를 다른 메서드로
	 * 부르면 무인증으로 열리지 않는다 — 메서드 없이 경로만 열면 이 요청들이 인가를 지나 401 이
	 * 아니게 된다.
	 */
	@ParameterizedTest(name = "{0} {1}")
	@CsvSource({
			"GET,/api/v1/accounts/email-verification",
			"GET,/api/v1/accounts/email-verification/confirm",
			"GET,/api/v1/accounts/password-reset",
			"GET,/api/v1/accounts/password-reset/confirm"
	})
	@DisplayName("무인증 경로를 다른 메서드로 부르면 토큰 없이 401 A001 이다")
	void 무인증_경로의_다른_메서드는_열리지_않는다(String method, String path) throws Exception {
		this.mockMvc.perform(request(HttpMethod.valueOf(method), path))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("A001"))
				.andExpect(jsonPath("$.error.message").value("인증이 필요합니다."));
	}

	/**
	 * 무인증 경로에 거부되는 토큰을 실어도 인증 경로와 같은 401 코드다.
	 *
	 * <p>sp-docs/plan/phase2-auth-member.md 의 AU-13 이 정한 테스트다. 화면이 무인증 요청에 저장된
	 * 토큰을 실을 때의 응답을 고정한다(같은 계획 §5.2). 코드의 경계는 sp-docs/api-contract.md §8.5
	 * 의 표다.
	 *
	 * <p>Bearer 토큰 필터는 인가 규칙과 무관하게 실린 토큰을 검증하고, 실패하면 인가에 닿기 전에
	 * 끊는다. 그래서 같은 {@code Authorization} 을 인증 경로({@code GET /api/v1/accounts/me})에 실은
	 * 응답을 함께 보고, 둘이 같은 코드인지 단언한다.
	 *
	 * <p><b>케이스는 필터가 끊는 토큰으로 한다</b> — AU-13 의 완료 기준이다. claim 계약 위반(예:
	 * 열거 밖 {@code role})은 여기서 단언하지 않는다 — AU-13 이 그 결과는 단언하지 말고 관측해
	 * 보고하라고 정했고, 무인증 경로의 그 응답은 같은 계획 §5.3 이 정본 개정으로 넘겼다. auth 는 그
	 * 계약을 {@code @CurrentAccount} 의 인자 해석에서 집행한다(§8.5 의 블록인용).
	 */
	@ParameterizedTest(name = "{0} {1} + {2}")
	@MethodSource("무인증_경로와_거부되는_토큰")
	@DisplayName("무인증 경로에 거부되는 토큰을 실으면 인증 경로와 같은 401 코드다")
	void 무인증_경로의_거부되는_토큰(HttpMethod method, String path, 거부되는_토큰 token) throws Exception {
		String authorization = authorizationOf(token);

		this.mockMvc.perform(get("/api/v1/accounts/me").header(HttpHeaders.AUTHORIZATION, authorization))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value(token.code));

		this.mockMvc.perform(request(method, path).header(HttpHeaders.AUTHORIZATION, authorization))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value(token.code))
				.andExpect(jsonPath("$.error.message").value(token.message));
	}

	static Stream<Arguments> 무인증_경로와_거부되는_토큰() {
		List<Arguments> paths = List.of(
				Arguments.of(HttpMethod.GET, "/api/v1/accounts/check-email"),
				Arguments.of(HttpMethod.POST, "/api/v1/auth/login"),
				Arguments.of(HttpMethod.POST, "/api/v1/accounts/email-verification/confirm"));
		return paths.stream().flatMap(path -> Stream.of(거부되는_토큰.values())
				.map(token -> Arguments.of(path.get()[0], path.get()[1], token)));
	}

	/**
	 * 선언 순서 결함은 두 경로를 <b>함께</b> 봐야 드러난다. {@code /accounts}(무인증)를 먼저
	 * 선언하면 {@code /accounts/me} 가 그 규칙에 먹혀 <b>내 계정이 무인증으로 열린다.</b>
	 */
	@Test
	@DisplayName("/accounts/me 가 /accounts 보다 먼저 선언되어 있다")
	void 경로_선언_순서() throws Exception {
		this.mockMvc.perform(get("/api/v1/accounts/me"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A001"));

		this.mockMvc.perform(post("/api/v1/accounts"))
				.andExpect(notUnauthorized());
	}

	@Test
	@DisplayName("선언되지 않은 경로는 인증을 요구한다")
	void 선언되지_않은_경로는_막힌다() throws Exception {
		this.mockMvc.perform(get("/api/v1/somewhere-new"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A001"));
	}

	// --- 인프라 경로 (sp-docs/security.md §5.1.1) ---

	@Test
	@DisplayName("토큰 없이 /swagger-ui.html 은 302 로 /swagger-ui/index.html 로 간다")
	void swagger_진입점은_인증_없이_열린다() throws Exception {
		this.mockMvc.perform(get("/swagger-ui.html"))
				.andExpect(status().is3xxRedirection())
				// /login 으로 가면 폼 로그인이 살아 있거나 permitAll 이 빠진 것이다
				.andExpect(redirectedUrl("/swagger-ui/index.html"));
	}

	@Test
	@DisplayName("토큰 없이 /swagger-ui/index.html 이 200 이다")
	void swagger_ui_는_인증_없이_열린다() throws Exception {
		this.mockMvc.perform(get("/swagger-ui/index.html"))
				.andExpect(status().isOk());
	}

	@Test
	@DisplayName("토큰 없이 /v3/api-docs 가 200 과 OpenAPI 문서를 돌려준다")
	void api_docs_는_인증_없이_열린다() throws Exception {
		this.mockMvc.perform(get("/v3/api-docs"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.openapi").exists())
				.andExpect(jsonPath("$.info.title").value("auth-service API"));
	}

	@Test
	@DisplayName("/actuator/health 는 인증 없이 열린다")
	void actuator_health_는_열린다() throws Exception {
		this.mockMvc.perform(get("/actuator/health"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("UP"));
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"/actuator", "/actuator/beans", "/actuator/env", "/actuator/metrics",
			"/actuator/configprops", "/actuator/mappings"})
	@DisplayName("health 외의 actuator 경로는 노출되지 않는다")
	void actuator_는_health_만_노출한다(String path) throws Exception {
		MvcResult result = this.mockMvc.perform(get(path)).andReturn();

		assertThat(result.getResponse().getStatus())
				.as("%s 가 열려 있으면 빈 목록·환경변수·매핑이 그대로 새어 나간다", path)
				.isIn(HttpStatus.UNAUTHORIZED.value(), HttpStatus.FORBIDDEN.value(),
						HttpStatus.NOT_FOUND.value());
	}

	@Test
	@DisplayName("유효한 토큰으로도 health 외의 actuator 경로는 403 A004 다")
	void actuator_는_인증해도_막힌다() throws Exception {
		this.mockMvc.perform(get("/actuator/beans").header(HttpHeaders.AUTHORIZATION, bearerToken()))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.error.code").value("A004"))
				.andExpect(jsonPath("$.error.message").value("권한이 없습니다."));
	}

	// --- STATELESS (sp-docs/security.md §1) ---

	@Test
	@DisplayName("세션이 생성되지 않고 세션 쿠키도 내려가지 않는다")
	void 세션이_생성되지_않는다() throws Exception {
		assertNoSession(this.mockMvc.perform(get("/api/v1/accounts/me")).andReturn());
		assertNoSession(this.mockMvc.perform(get("/test/current-account")
				.header(HttpHeaders.AUTHORIZATION, bearerToken())).andReturn());
	}

	// --- @CurrentAccount (sp-docs/security.md §4) ---

	@Test
	@DisplayName("@CurrentAccount 가 검증된 토큰의 sub·role 로 채워진다")
	void current_account_가_토큰에서_채워진다() throws Exception {
		this.mockMvc.perform(get("/test/current-account")
						.header(HttpHeaders.AUTHORIZATION, bearerToken()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.accountId").value(7))
				.andExpect(jsonPath("$.role").value("ADMIN"))
				.andExpect(jsonPath("$.nickname").doesNotExist());
	}

	// --- CORS (sp-docs/security.md §1.1) ---

	@Test
	@DisplayName("CORS 의 메서드·헤더·allowCredentials·노출 헤더가 정본 값이고 * 가 없다")
	void cors_설정값이_정본과_일치한다() {
		assertThat(this.corsConfigurationSource).isInstanceOf(UrlBasedCorsConfigurationSource.class);
		CorsConfiguration configuration =
				((UrlBasedCorsConfigurationSource) this.corsConfigurationSource)
						.getCorsConfigurations().get("/**");

		assertThat(configuration).isNotNull();
		assertThat(configuration.getAllowedOrigins()).isNotEmpty().doesNotContain("*");
		assertThat(configuration.getAllowedOriginPatterns()).isNullOrEmpty();
		assertThat(configuration.getAllowedMethods())
				.containsExactlyInAnyOrder("GET", "POST", "PATCH", "DELETE");
		assertThat(configuration.getAllowedHeaders())
				.containsExactlyInAnyOrder("Authorization", "Content-Type");
		assertThat(configuration.getAllowCredentials())
				.as("토큰을 Authorization 헤더로 보내므로 쿠키를 허용할 이유가 없다")
				.isFalse();
		assertThat(configuration.getExposedHeaders())
				.as("노출하지 않으면 브라우저가 Retry-After 를 스크립트에 숨겨 화면이 429 뒤 언제 다시 할지 "
						+ "말할 수 없다 (sp-docs/security.md §1.1)")
				.containsExactly("Retry-After");
	}

	@Test
	@DisplayName("허용 오리진에 * 가 들어오면 기동이 실패한다")
	void cors_에_와일드카드를_주면_기동_실패한다() {
		SecurityConfig securityConfig = new SecurityConfig(this.securityErrorResponder);

		assertThatThrownBy(() -> securityConfig.corsConfigurationSource(List.of(ALLOWED_ORIGIN, "*")))
				.as("값이 환경에서 오므로 * 금지를 지키는 지점은 여기뿐이다")
				.isInstanceOf(IllegalStateException.class);
		assertThatThrownBy(() -> securityConfig.corsConfigurationSource(List.of()))
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	@DisplayName("화이트리스트의 오리진은 preflight 를 통과하고 그 밖의 오리진은 막힌다")
	void cors_preflight() throws Exception {
		this.mockMvc.perform(options("/api/v1/auth/login")
						.header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
						.header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED_ORIGIN));

		this.mockMvc.perform(options("/api/v1/auth/login")
						.header(HttpHeaders.ORIGIN, "http://not-allowed.example")
						.header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
				.andExpect(status().isForbidden());
	}

	// --- 기능 단계가 쓸 빈 (sp-docs/plan/phase1.md §4 AU-04 "의존성 빈 선제 준비") ---

	@Test
	@DisplayName("AccountService·AuthService 가 쓸 빈이 이 항목 완료 시점에 전부 있다")
	void 기능_단계가_쓸_빈이_준비되어_있다() {
		// 하나라도 없으면 AU-05 이후가 기반 경로를 고쳐야 해서 막힌다 (§2.1)
		assertThat(this.applicationContext.getBean(AccountRepository.class)).isNotNull();
		assertThat(this.applicationContext.getBean(AccountReader.class)).isNotNull();
		assertThat(this.applicationContext.getBean(PasswordEncoder.class))
				.as("BCrypt strength 10 (sp-docs/security.md §1)")
				.isInstanceOf(BCryptPasswordEncoder.class);
		assertThat(this.applicationContext.getBean(JwtTokenProvider.class)).isNotNull();
		assertThat(this.applicationContext.getBean(RefreshTokenRepository.class)).isNotNull();
	}

	private String bearerToken() {
		return "Bearer " + this.jwtTokenProvider.issue(7L, Role.ADMIN).accessToken();
	}

	private String authorizationOf(거부되는_토큰 token) {
		return switch (token) {
			// RFC 6750 의 b64token 문법 위반 — 리졸버가 디코더 앞에서 끊는다 (§8.5 의 블록인용)
			case 문법_위반 -> "Bearer not!a!token";
			// 문법은 맞지만 JWT 가 아니다
			case JWT_아님 -> "Bearer notajwt";
			case 서명_불일치 -> "Bearer " + TestTokens.tamperSignature(
					this.jwtTokenProvider.issue(7L, Role.USER).accessToken());
			// 한 시간 전에 만료됐다. 만료 폭은 픽스처 산수이고 정책값이 아니다 — 디코더의 기본
			// clock skew 60초보다 충분히 과거면 된다
			case 만료 -> "Bearer " + TestTokens.signed(this.jwtEncoder, 7L, Role.USER,
					Instant.now().minus(Duration.ofHours(2)), Duration.ofHours(1));
		};
	}

	/** 이 테스트가 싣는 토큰. 각 줄과 그 코드는 sp-docs/api-contract.md §8.5 의 표, 메시지는 §8.1 이다. */
	enum 거부되는_토큰 {

		문법_위반("A001", "인증이 필요합니다."),
		JWT_아님("A002", "유효하지 않은 토큰입니다."),
		서명_불일치("A002", "유효하지 않은 토큰입니다."),
		만료("A003", "만료된 토큰입니다.");

		private final String code;
		private final String message;

		거부되는_토큰(String code, String message) {
			this.code = code;
			this.message = message;
		}

	}

	private void assertNoSession(MvcResult result) {
		assertThat(result.getRequest().getSession(false))
				.as("SessionCreationPolicy.STATELESS 인데 세션이 생겼다")
				.isNull();
		assertThat(result.getResponse().getHeaders(HttpHeaders.SET_COOKIE))
				.noneSatisfy(value -> assertThat(value).contains("JSESSIONID"));
	}

	/** 컨트롤러가 없는 경로는 404 가 되므로 "200"이 아니라 "401 이 아님"으로 단언한다. */
	private static ResultMatcher notUnauthorized() {
		return result -> assertThat(result.getResponse().getStatus())
				.as("인가 규칙이 빠지면 Boot 기본 동작으로 401 이 된다 (sp-docs/security.md §5.1.1)")
				.isNotEqualTo(HttpStatus.UNAUTHORIZED.value());
	}

	/** 프로브 컨트롤러를 이 컨텍스트에만 등록한다 ({@link CurrentAccountProbeController} 주석 참조). */
	@TestConfiguration
	static class ProbeControllerConfig {

		@Bean
		CurrentAccountProbeController currentAccountProbeController() {
			return new CurrentAccountProbeController();
		}

	}

}
