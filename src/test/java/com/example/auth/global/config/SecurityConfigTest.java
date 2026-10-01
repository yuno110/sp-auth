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
import com.example.securityprobe.CurrentAccountProbeController;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
 * sp-docs/plan/phase1.md §4 AU-04 의 "검증" 표 중 인가 쪽을 테스트로 옮긴 것이다.
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
			"POST,/api/v1/auth/logout"
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
			"POST,/api/v1/auth/reissue"
	})
	@DisplayName("무인증 경로는 토큰 없이도 401 이 아니다")
	void 무인증_경로(String method, String path) throws Exception {
		this.mockMvc.perform(request(HttpMethod.valueOf(method), path))
				.andExpect(notUnauthorized());
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

	// --- CORS (sp-docs/security.md §1) ---

	@Test
	@DisplayName("CORS 설정에 * 가 없다")
	void cors_에_와일드카드가_없다() {
		assertThat(this.corsConfigurationSource).isInstanceOf(UrlBasedCorsConfigurationSource.class);
		CorsConfiguration configuration =
				((UrlBasedCorsConfigurationSource) this.corsConfigurationSource)
						.getCorsConfigurations().get("/**");

		assertThat(configuration).isNotNull();
		assertThat(configuration.getAllowedOrigins()).isNotEmpty().doesNotContain("*");
		assertThat(configuration.getAllowedOriginPatterns()).isNullOrEmpty();
		assertThat(configuration.getAllowedMethods()).doesNotContain("*");
		assertThat(configuration.getAllowedHeaders()).doesNotContain("*");
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
