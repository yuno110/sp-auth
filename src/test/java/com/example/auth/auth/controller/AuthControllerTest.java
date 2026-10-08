package com.example.auth.auth.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.support.TestRsaKeys;
import com.example.auth.support.TestTokens;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * sp-docs/plan/phase1.md §4 AU-06·AU-07 의 "검증" 표 중 HTTP 쪽을 테스트로 옮긴 것이다.
 * 저장·Claim·회전은 {@link com.example.auth.auth.service.AuthServiceTest} 가 본다.
 *
 * <p>정본은 sp-docs/api-contract.md §2.1 §9.2 §8.1 §8.4 다.
 *
 * <p>인가 필터를 포함한 전 구간을 지난다 — {@code login}·{@code reissue} 는 무인증,
 * {@code logout} 은 인증이다 (sp-docs/security.md §5.1). 그래서 필터 단계의
 * {@code A001}/{@code A002}/{@code A003} 구분도 여기서 본다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	private static final String WRONG_PASSWORD = "Other1!pw";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 테스트가 만든 것이 아니다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	/** sp-docs/api-contract.md §8.4. */
	private static final String LOGIN_FAILED_MESSAGE = "이메일 또는 비밀번호가 일치하지 않습니다.";

	/** sp-docs/api-contract.md §8.1 {@code A002}. */
	private static final String INVALID_TOKEN_MESSAGE = "유효하지 않은 토큰입니다.";

	/** sp-docs/api-contract.md §8.1 {@code A003}. */
	private static final String EXPIRED_TOKEN_MESSAGE = "만료된 토큰입니다.";

	/** sp-docs/security.md §1: Access 30분. */
	private static final int ACCESS_TOKEN_SECONDS = 1800;

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	/** 만료된 토큰 픽스처를 애플리케이션의 서명 키로 만든다 ({@link TestTokens}). */
	@Autowired
	private JwtEncoder jwtEncoder;

	/**
	 * <b>seed 행은 남긴다.</b> H2 는 테스트 클래스 사이에 공유되므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 여기서 지우면
	 * {@code AdminSeedTest} 가 자기와 무관한 이유로 깨진다.
	 *
	 * <p>{@code fk_refresh_token_account} 가 있으므로 토큰을 먼저 지운다.
	 */
	@AfterEach
	void 정리() {
		this.refreshTokenRepository.deleteAll();
		this.refreshTokenRepository.flush();
		this.accountRepository.deleteAll(this.accountRepository.findAll().stream()
				.filter(account -> !ADMIN_EMAIL.equals(account.getEmail()))
				.toList());
	}

	@Test
	@DisplayName("로그인은 200 과 TokenResponse 를 반환한다")
	void 정상_로그인() throws Exception {
		계정을_만든다("user@example.com");

		String body = this.mockMvc.perform(login("user@example.com", RAW_PASSWORD))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.error").isEmpty())
				.andExpect(jsonPath("$.data.grantType").value("Bearer"))
				.andExpect(jsonPath("$.data.accessToken").isNotEmpty())
				.andExpect(jsonPath("$.data.refreshToken").isNotEmpty())
				.andExpect(jsonPath("$.data.accessTokenExpiresIn").value(ACCESS_TOKEN_SECONDS))
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.as("비밀번호는 어떤 응답에도 넣지 않는다 (sp-docs/requirements/member.md §3 규칙 2)")
				.doesNotContain(RAW_PASSWORD)
				.doesNotContain("password");
	}

	@Test
	@DisplayName("비밀번호가 틀리면 401 AU003 이다")
	void 비밀번호_불일치() throws Exception {
		계정을_만든다("wrong-pw@example.com");

		this.mockMvc.perform(login("wrong-pw@example.com", WRONG_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("AU003"))
				.andExpect(jsonPath("$.error.message").value(LOGIN_FAILED_MESSAGE));
	}

	/**
	 * <b>이 항목의 핵심 단언이다.</b> 응답 본문을 통째로 비교한다 — 코드만 보면 메시지나
	 * {@code fieldErrors} 로 차이가 새는 것을 놓친다. 어느 쪽이 틀렸는지 드러나면 이메일 존재
	 * 여부를 알려주는 열거 취약점이 된다 (sp-docs/plan/phase1.md §4 AU-06).
	 */
	@Test
	@DisplayName("없는 이메일의 응답이 비밀번호 불일치와 완전히 같다")
	void 없는_이메일과_비밀번호_불일치가_구별되지_않는다() throws Exception {
		계정을_만든다("real@example.com");

		MvcResult 비밀번호_불일치 = this.mockMvc.perform(login("real@example.com", WRONG_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andReturn();
		MvcResult 없는_이메일 = this.mockMvc.perform(login("nobody@example.com", RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andReturn();

		assertThat(없는_이메일.getResponse().getContentAsString(StandardCharsets.UTF_8))
				.isEqualTo(비밀번호_불일치.getResponse().getContentAsString(StandardCharsets.UTF_8));
		assertThat(없는_이메일.getResponse().getStatus())
				.isEqualTo(비밀번호_불일치.getResponse().getStatus());
	}

	@Test
	@DisplayName("탈퇴한 계정은 비밀번호가 맞아도 401 이다")
	void 탈퇴_계정_로그인() throws Exception {
		Account account = 계정을_만든다("bye@example.com");
		account.withdraw();
		this.accountRepository.saveAndFlush(account);

		this.mockMvc.perform(login("bye@example.com", RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU003"))
				.andExpect(jsonPath("$.data").isEmpty());
	}

	/**
	 * 자격증명이 빠진 요청도 401 이다 — 정본이 로그인에 400 을 정하지 않았다
	 * (sp-docs/api-contract.md §2.1 §8.4). 이유는
	 * {@link com.example.auth.auth.dto.LoginRequest} 에 적었다.
	 *
	 * <p>표에 없는 케이스지만 <b>500 이 새지 않는지</b>를 함께 본다 —
	 * {@code BCrypt.matches(null, ...)} 는 {@code IllegalArgumentException} 을 던진다.
	 */
	@Test
	@DisplayName("자격증명이 비어 있으면 500 이 아니라 401 AU003 이다")
	void 자격증명_누락() throws Exception {
		계정을_만든다("blank@example.com");

		for (String json : new String[] {
				"{}",
				"{\"email\": \"blank@example.com\"}",
				"{\"email\": \"blank@example.com\", \"password\": \"\"}",
				"{\"password\": \"" + RAW_PASSWORD + "\"}"
		}) {
			this.mockMvc.perform(loginRequest(json))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.error.code").value("AU003"));
		}
	}

	/**
	 * 검증 표의 마지막 행. <b>{@code GET /accounts/me} 는 AU-10 이 만든다</b> — 지금은 404 다.
	 * 보는 것은 <b>발급한 토큰이 인가 필터를 통과하는가</b>이므로 "401 이 아님"으로 단언한다.
	 * AU-10 이 엔드포인트를 만든 뒤에도 이 단언은 그대로 유효하다.
	 */
	@Test
	@DisplayName("로그인으로 받은 토큰으로 /accounts/me 에 접근하면 401 이 아니다")
	void 발급된_토큰은_인증을_통과한다() throws Exception {
		계정을_만든다("token@example.com");

		String body = this.mockMvc.perform(login("token@example.com", RAW_PASSWORD))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
		String accessToken = JsonPath.read(body, "$.data.accessToken");

		MvcResult result = this.mockMvc.perform(get("/api/v1/accounts/me")
						.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
				.andReturn();

		assertThat(result.getResponse().getStatus())
				.as("401 이면 발급한 토큰이 자기 서비스의 검증을 통과하지 못한 것이다")
				.isNotEqualTo(HttpStatus.UNAUTHORIZED.value());
	}

	// --- AU-07 재발급·로그아웃 (sp-docs/api-contract.md §2.1 §8.1) ---

	@Test
	@DisplayName("재발급은 200 과 새 TokenResponse 를 반환하고 저장값이 그것으로 교체된다")
	void 정상_재발급() throws Exception {
		계정을_만든다("reissue@example.com");
		IssuedTokens 로그인 = 로그인한다("reissue@example.com");

		String body = this.mockMvc.perform(reissue(로그인.refreshToken()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.error").isEmpty())
				.andExpect(jsonPath("$.data.grantType").value("Bearer"))
				.andExpect(jsonPath("$.data.accessToken").isNotEmpty())
				.andExpect(jsonPath("$.data.refreshToken").isNotEmpty())
				.andExpect(jsonPath("$.data.accessTokenExpiresIn").value(ACCESS_TOKEN_SECONDS))
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(this.refreshTokenRepository.findAll())
				.as("회전된 값이 저장되어 있어야 다음 재발급이 성립한다")
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(JsonPath.read(body, "$.data.refreshToken"));
	}

	/**
	 * 같은 로그인의 Access Token 을 Refresh Token 자리에 넣는다 — 서명과 만료가 멀쩡하고
	 * 저장값과만 다르다. 응답이 401 {@code A002} 여야 한다 (sp-docs/api-contract.md §8.1).
	 */
	@Test
	@DisplayName("저장값과 다른 Refresh Token 은 401 A002 다")
	void 저장값과_다른_토큰_재발급() throws Exception {
		계정을_만든다("mismatch@example.com");
		IssuedTokens 로그인 = 로그인한다("mismatch@example.com");

		this.mockMvc.perform(reissue(로그인.accessToken()))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("A002"))
				.andExpect(jsonPath("$.error.message").value(INVALID_TOKEN_MESSAGE));
	}

	@Test
	@DisplayName("만료된 Refresh Token 으로 재발급하면 401 A003 이다")
	void 만료된_토큰_재발급() throws Exception {
		Long accountId = 계정을_만든다("expired-reissue@example.com").getId();

		this.mockMvc.perform(reissue(만료된_토큰(accountId)))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A003"))
				.andExpect(jsonPath("$.error.message").value(EXPIRED_TOKEN_MESSAGE));
	}

	@Test
	@DisplayName("로그아웃은 204 와 빈 본문을 반환하고 refresh_token 행을 지운다")
	void 정상_로그아웃() throws Exception {
		계정을_만든다("logout@example.com");
		IssuedTokens 로그인 = 로그인한다("logout@example.com");
		assertThat(this.refreshTokenRepository.findAll()).hasSize(1);

		String body = this.mockMvc.perform(logout(로그인.accessToken()))
				.andExpect(status().isNoContent())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body).as("204 에는 본문을 담지 않는다").isEmpty();
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	@Test
	@DisplayName("로그아웃 후 같은 Refresh Token 으로 재발급하면 401 A002 다")
	void 로그아웃_후_재발급() throws Exception {
		계정을_만든다("logout-reissue@example.com");
		IssuedTokens 로그인 = 로그인한다("logout-reissue@example.com");

		this.mockMvc.perform(logout(로그인.accessToken())).andExpect(status().isNoContent());

		this.mockMvc.perform(reissue(로그인.refreshToken()))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A002"));
		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 재발급이 행을 다시 만들지 않는다")
				.isEmpty();
	}

	/**
	 * <b>이 항목의 핵심 단언 하나다.</b> AU-04 는 필터 단계의 모든 인증 실패를 {@code A001} 로
	 * 냈다. 세 경우를 <b>한 테스트에서</b> 보는 것은 구분이 실제로 갈리는지가 요점이기 때문이다 —
	 * 하나씩 보면 셋이 같은 코드로 수렴해도 눈에 띄지 않는다.
	 *
	 * <p>상태·메시지는 sp-docs/api-contract.md §8.1 이 정본이다.
	 */
	@Test
	@DisplayName("보호 경로에서 토큰 없음은 A001, 서명 변조는 A002, 만료는 A003 이다")
	void 필터_단계의_세_코드가_갈린다() throws Exception {
		Long accountId = 계정을_만든다("filter@example.com").getId();
		IssuedTokens 로그인 = 로그인한다("filter@example.com");

		this.mockMvc.perform(post("/api/v1/auth/logout"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A001"))
				.andExpect(jsonPath("$.error.message").value("인증이 필요합니다."));

		this.mockMvc.perform(logout(TestTokens.tamperSignature(로그인.accessToken())))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A002"))
				.andExpect(jsonPath("$.error.message").value(INVALID_TOKEN_MESSAGE));

		this.mockMvc.perform(logout(만료된_토큰(accountId)))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A003"))
				.andExpect(jsonPath("$.error.message").value(EXPIRED_TOKEN_MESSAGE));

		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 로그아웃은 아무것도 지우지 않는다 — 요청이 컨트롤러에 닿지 않는다")
				.hasSize(1);
	}

	/**
	 * 한 시간 전에 만료된 토큰. <b>만료 폭은 픽스처 산수이고 정책값이 아니다</b> — 디코더의 기본
	 * clock skew 가 60초이므로 그보다 충분히 과거이면 된다.
	 *
	 * <p>Access·Refresh 는 claim 집합이 같으므로(sp-docs/api-contract.md §6) 같은 값으로 양쪽
	 * 경로를 본다.
	 */
	private String 만료된_토큰(Long accountId) {
		return TestTokens.signed(this.jwtEncoder, accountId, Role.USER,
				Instant.now().minus(Duration.ofHours(2)), Duration.ofHours(1));
	}

	private IssuedTokens 로그인한다(String email) throws Exception {
		String body = this.mockMvc.perform(login(email, RAW_PASSWORD))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		return new IssuedTokens(
				JsonPath.read(body, "$.data.accessToken"),
				JsonPath.read(body, "$.data.refreshToken"));
	}

	private static MockHttpServletRequestBuilder reissue(String refreshToken) {
		return post("/api/v1/auth/reissue")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content("{\"refreshToken\": \"" + refreshToken + "\"}");
	}

	private static MockHttpServletRequestBuilder logout(String accessToken) {
		return post("/api/v1/auth/logout")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
	}

	/** 로그인 응답에서 꺼낸 두 토큰. */
	private record IssuedTokens(String accessToken, String refreshToken) { }

	private static MockHttpServletRequestBuilder login(String email, String password) {
		return loginRequest("{\"email\": \"" + email + "\", \"password\": \"" + password + "\"}");
	}

	private static MockHttpServletRequestBuilder loginRequest(String json) {
		return post("/api/v1/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

	/** 프로필은 만들지 않는다 — auth 는 프로필을 소유하지 않는다. */
	private Account 계정을_만든다(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				// 런타임에 인코딩한다. 해시를 테스트 파일에 적으면 커밋되는 픽스처가 된다
				// (sp-docs/requirements/member.md §10.2)
				.password(this.passwordEncoder.encode(RAW_PASSWORD))
				.build());
	}

}
