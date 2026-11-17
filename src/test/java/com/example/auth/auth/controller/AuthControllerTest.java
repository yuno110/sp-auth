package com.example.auth.auth.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.Role;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.account.support.AccountTokens;
import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.support.MutableClock;
import com.example.auth.support.TestRsaKeys;
import com.example.auth.support.TestTokens;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * sp-docs/plan/phase1.md §4 AU-06·AU-07 과 D-17 의 "검증" 표 중 HTTP 쪽을 테스트로 옮긴 것이다.
 * 저장·Claim·회전은 {@link com.example.auth.auth.service.AuthServiceTest} 가 본다.
 *
 * <p>정본은 sp-docs/api-contract.md §2.1 §9.2 §8.1 §8.4 다.
 *
 * <p>인가 필터를 포함한 전 구간을 지난다 — {@code login}·{@code reissue} 는 무인증,
 * {@code logout} 은 인증이다 (sp-docs/security.md §5.1). 그래서 필터 단계의
 * {@code A001}/{@code A002}/{@code A003} 구분도 여기서 본다.
 *
 * <p>2차 AU-18(로그인 잠금)의 검증 표 중 HTTP 쪽 — 상태·본문, 잠금 시각 너머의 200, 비밀번호 변경·탈퇴의 {@code AU004} —
 * 도 여기 있다(sp-docs/plan/phase2-auth-member.md). 카운터의 값과 트랜잭션 경계는
 * {@link com.example.auth.auth.service.AuthServiceTest}·{@link com.example.auth.auth.service.LoginAttemptServiceTest} 가 본다.
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

	/** AU-16. sp-docs/api-contract.md §8.4 {@code AU006}, §9.10. */
	private static final String EMAIL_NOT_VERIFIED_MESSAGE = "이메일 인증이 필요합니다.";

	/** AU-18. sp-docs/api-contract.md §8.4 {@code AU005}. */
	private static final String LOGIN_LOCKED_MESSAGE = "로그인 시도가 많아 잠시 로그인할 수 없습니다.";

	/** AU-18 — 비밀번호 변경의 새 비밀번호. 규칙(sp-docs/requirements/member.md §2)을 만족한다. */
	private static final String NEW_PASSWORD = "NewPassw0rd!";

	/**
	 * AU-18 의 테스트가 시계를 멈추는 시각. 잠금(15분)은 이 시각에 리터럴로 더한다 — 카운터 빈의 상수를 읽어 기대값을 만들면
	 * 상수를 바꾼 변이도 통과한다.
	 */
	private static final LocalDateTime LOCK_NOW = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	/** sp-docs/security.md §1: Access 30분. */
	private static final int ACCESS_TOKEN_SECONDS = 1800;

	/**
	 * AU-18 — 앱 시계를 바꿔 끼운다. 고정하지 않은 테스트에서는 시스템 시계다 ({@link MutableClock}). 토큰의 발급 시각은 이
	 * 시계가 아니라 시스템 시계에서 온다({@code JwtTokenProvider#issue}) — 시계를 멈춰도 발급한 토큰은 그대로 검증된다.
	 */
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

	/** 직전 토큰이 있는 행을 심을 때 조건부 UPDATE 를 트랜잭션 안에서 부른다. */
	@Autowired
	private TransactionTemplate transactionTemplate;

	/** AU-16 — 인증 확인을 거친 로그인의 토큰 행. 이 클래스는 가입을 부르지 않으므로 다른 스레드가 만드는 행은 없다. */
	@Autowired
	private AccountTokenRepository accountTokenRepository;

	/** AU-16 — ADMIN seed 의 행을 잠시 바꾸고 되돌린다. */
	@Autowired
	private JdbcTemplate jdbcTemplate;

	/**
	 * <b>seed 행은 남긴다.</b> H2 는 테스트 클래스 사이에 공유되므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 여기서 지우면
	 * {@code AdminSeedTest} 가 자기와 무관한 이유로 깨진다.
	 *
	 * <p>{@code fk_refresh_token_account} 가 있으므로 토큰을 먼저 지운다. AU-16 의 테스트가 만드는
	 * {@code account_token} 행도 같은 이유로 먼저 지운다({@code fk_account_token_account}).
	 *
	 * <p>AU-18 부터 로그인 실패가 {@code login_attempt} 행을 커밋한다. 그 테이블은 계정을 참조하지 않지만 남기면 같은 이메일을
	 * 쓰는 다음 테스트의 카운터가 이어진다 — 먼저 지운다.
	 */
	@AfterEach
	void 정리() {
		CLOCK.reset();
		this.jdbcTemplate.update("delete from login_attempt");
		this.accountTokenRepository.deleteAllInBatch();
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
	 *
	 * <p>AU-18 — 빈 값은 세지 않는다. 있는 이메일 + 빈 비밀번호도 {@code login_attempt} 행을 만들지 않는다
	 * (sp-docs/requirements/member.md §12.1 의 1).
	 */
	@Test
	@DisplayName("자격증명이 비어 있으면 500 이 아니라 401 AU003 이고 login_attempt 행이 생기지 않는다")
	void 자격증명_누락() throws Exception {
		계정을_만든다("blank@example.com");

		for (String json : new String[] {
				"{}",
				"{\"email\": \"blank@example.com\"}",
				"{\"email\": \"blank@example.com\", \"password\": \"\"}",
				"{\"email\": \"blank@example.com\", \"password\": \"   \"}",
				"{\"password\": \"" + RAW_PASSWORD + "\"}"
		}) {
			this.mockMvc.perform(loginRequest(json))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.error.code").value("AU003"));
		}

		assertThat(키들()).isEmpty();
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
	@DisplayName("로그아웃은 본문이 저장된 토큰이면 204 와 빈 본문을 반환하고 refresh_token 행을 지운다")
	void 정상_로그아웃() throws Exception {
		계정을_만든다("logout@example.com");
		IssuedTokens 로그인 = 로그인한다("logout@example.com");
		assertThat(this.refreshTokenRepository.findAll()).hasSize(1);

		String body = this.mockMvc.perform(logout(로그인.accessToken(), 로그인.refreshToken()))
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

		this.mockMvc.perform(logout(로그인.accessToken(), 로그인.refreshToken()))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(reissue(로그인.refreshToken()))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A002"));
		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 재발급이 행을 다시 만들지 않는다")
				.isEmpty();
	}

	// --- D-17 재사용 유예·로그아웃의 대조 (sp-docs/requirements/member.md §6.3·§6.4) ---

	@Test
	@DisplayName("회전 직후 직전 토큰으로 재발급하면 200 이고 Refresh Token 은 지금 저장된 값이다")
	void 유예_안의_직전_토큰_재발급() throws Exception {
		Account account = 계정을_만든다("grace@example.com");
		String 직전_토큰 = 저장된_세션을_만든다(account);
		String 회전된_토큰 = JsonPath.read(this.mockMvc.perform(reissue(직전_토큰))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8), "$.data.refreshToken");

		this.mockMvc.perform(reissue(직전_토큰))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.grantType").value("Bearer"))
				.andExpect(jsonPath("$.data.accessToken").isNotEmpty())
				.andExpect(jsonPath("$.data.refreshToken").value(회전된_토큰))
				.andExpect(jsonPath("$.data.accessTokenExpiresIn").value(ACCESS_TOKEN_SECONDS));

		assertThat(this.refreshTokenRepository.findAll())
				.singleElement()
				.satisfies(row -> {
					assertThat(row.getToken()).isEqualTo(회전된_토큰);
					assertThat(row.getPreviousToken()).isEqualTo(직전_토큰);
				});
	}

	@Test
	@DisplayName("로그아웃 — 본문이 직전 토큰이면 204 이고 행을 지운다")
	void 직전_토큰으로_로그아웃() throws Exception {
		Account account = 계정을_만든다("logout-previous@example.com");
		IssuedTokens 로그인 = 로그인한다("logout-previous@example.com");
		String 직전_토큰 = 저장된_세션을_만든다(account);
		this.mockMvc.perform(reissue(직전_토큰)).andExpect(status().isOk());

		this.mockMvc.perform(logout(로그인.accessToken(), 직전_토큰))
				.andExpect(status().isNoContent());

		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	@Test
	@DisplayName("로그아웃 — 본문이 저장값·직전 토큰 어느 쪽과도 다르거나 JWT 가 아니면 204 이고 행이 그대로다")
	void 맞지_않는_토큰으로_로그아웃() throws Exception {
		Account account = 계정을_만든다("logout-mismatch@example.com");
		IssuedTokens 로그인 = 로그인한다("logout-mismatch@example.com");
		String 다른_토큰 = TestTokens.signed(this.jwtEncoder, account.getId(), Role.USER,
				Instant.now().minusSeconds(30), Duration.ofDays(14));

		for (String 제시 : new String[] {다른_토큰, 로그인.accessToken(), "not-a-jwt"}) {
			this.mockMvc.perform(logout(로그인.accessToken(), 제시))
					.andExpect(status().isNoContent());
		}

		assertThat(this.refreshTokenRepository.findAll())
				.as("서명을 검증하지 않고 문자열 대조로만 판정한다 — 맞지 않으면 아무것도 하지 않는다")
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(로그인.refreshToken());
	}

	/**
	 * 서명·만료를 검증하지 않는다 — 만료된 토큰도 문자열이 맞으면 지운다
	 * (sp-docs/requirements/member.md §6.4). 만료 JWT 는 과거 시각으로 서명해 만든다
	 * ({@link TestTokens#signed}).
	 */
	@Test
	@DisplayName("로그아웃 — 본문이 만료된 저장 토큰·직전 토큰 문자열이어도 204 이고 행을 지운다")
	void 만료된_토큰으로_로그아웃() throws Exception {
		Account account = 계정을_만든다("logout-expired@example.com");
		IssuedTokens 로그인 = 로그인한다("logout-expired@example.com");
		String 만료된_저장_토큰 = 만료된_토큰(account.getId());
		String 만료된_직전_토큰 = TestTokens.signed(this.jwtEncoder, account.getId(), Role.USER,
				Instant.now().minus(Duration.ofHours(3)), Duration.ofHours(1));

		// 저장 토큰이 만료된 행
		세션을_심는다(account, 만료된_저장_토큰, null);
		this.mockMvc.perform(logout(로그인.accessToken(), 만료된_저장_토큰))
				.andExpect(status().isNoContent());
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();

		// 직전 토큰이 만료된 행
		세션을_심는다(account, 로그인.refreshToken(), 만료된_직전_토큰);
		this.mockMvc.perform(logout(로그인.accessToken(), 만료된_직전_토큰))
				.andExpect(status().isNoContent());
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	@Test
	@DisplayName("로그아웃 — refreshToken 이 없거나 null·빈 문자열이면 400 C001, fieldErrors 에 refreshToken, 행 그대로")
	void refreshToken_누락_로그아웃() throws Exception {
		계정을_만든다("logout-missing@example.com");
		IssuedTokens 로그인 = 로그인한다("logout-missing@example.com");

		for (String json : new String[] {"{}", "{\"refreshToken\": null}", "{\"refreshToken\": \"\"}",
				"{\"refreshToken\": \"   \"}"}) {
			this.mockMvc.perform(logoutWithBody(로그인.accessToken(), json))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.success").value(false))
					.andExpect(jsonPath("$.error.code").value("C001"))
					.andExpect(jsonPath("$.error.fieldErrors.length()").value(1))
					.andExpect(jsonPath("$.error.fieldErrors[0].field").value("refreshToken"));
		}

		assertThat(this.refreshTokenRepository.findAll())
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(로그인.refreshToken());
	}

	@Test
	@DisplayName("로그아웃 — 행이 없어도 204 다")
	void 행이_없을_때_로그아웃() throws Exception {
		계정을_만든다("logout-norow@example.com");
		IssuedTokens 로그인 = 로그인한다("logout-norow@example.com");
		this.refreshTokenRepository.deleteAll();
		this.refreshTokenRepository.flush();

		this.mockMvc.perform(logout(로그인.accessToken(), 로그인.refreshToken()))
				.andExpect(status().isNoContent());
		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
	}

	/**
	 * 지울 계정은 Access Token 의 {@code sub} 가 정한다 — 본문의 토큰이 다른 계정의 저장값과
	 * 같아도 그 계정의 행을 지우지 않는다 (sp-docs/requirements/member.md §6.4).
	 */
	@Test
	@DisplayName("로그아웃 — A 의 Access Token 에 본문이 B 의 저장된 토큰이면 204 이고 B 의 행이 그대로다")
	void 다른_계정의_토큰으로_로그아웃() throws Exception {
		계정을_만든다("logout-a@example.com");
		Account b = 계정을_만든다("logout-b@example.com");
		IssuedTokens a로그인 = 로그인한다("logout-a@example.com");
		IssuedTokens b로그인 = 로그인한다("logout-b@example.com");

		this.mockMvc.perform(logout(a로그인.accessToken(), b로그인.refreshToken()))
				.andExpect(status().isNoContent());

		assertThat(this.refreshTokenRepository.findByAccountId(b.getId()))
				.get()
				.extracting(RefreshToken::getToken)
				.isEqualTo(b로그인.refreshToken());
		assertThat(this.refreshTokenRepository.findAll()).hasSize(2);
	}

	/**
	 * 늦게 도착한 옛 세션의 로그아웃이 새 세션을 지우지 않는다 (plan D-17 의 결함 2).
	 *
	 * <p>세션 A 의 토큰은 과거 시각으로 서명해 심는다 — 같은 초에 로그인을 두 번 하면 두 토큰의
	 * 문자열이 같아 세션을 가를 수 없다 (sp-docs/requirements/member.md §6.2).
	 */
	@Test
	@DisplayName("로그인 A → 같은 계정 로그인 B → A 의 로그아웃이 늦게 도착하면 204 이고 B 의 행이 남아 재발급이 된다")
	void 늦은_로그아웃은_새_세션을_지우지_않는다() throws Exception {
		Account account = 계정을_만든다("logout-late@example.com");
		Instant a발급 = Instant.now().minusSeconds(10);
		String a토큰 = 저장된_세션을_만든다(account);
		String a액세스 = TestTokens.signed(this.jwtEncoder, account.getId(), Role.USER, a발급,
				Duration.ofSeconds(ACCESS_TOKEN_SECONDS));
		IssuedTokens b로그인 = 로그인한다("logout-late@example.com");

		this.mockMvc.perform(logout(a액세스, a토큰))
				.andExpect(status().isNoContent());

		assertThat(this.refreshTokenRepository.findAll())
				.singleElement()
				.extracting(RefreshToken::getToken)
				.isEqualTo(b로그인.refreshToken());
		this.mockMvc.perform(reissue(b로그인.refreshToken()))
				.andExpect(status().isOk());
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

		this.mockMvc.perform(logout(TestTokens.tamperSignature(로그인.accessToken()), 로그인.refreshToken()))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A002"))
				.andExpect(jsonPath("$.error.message").value(INVALID_TOKEN_MESSAGE));

		this.mockMvc.perform(logout(만료된_토큰(accountId), 로그인.refreshToken()))
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

	// --- AU-16 미인증 로그인 차단 (sp-docs/api-contract.md §2.1 의 표, §9.10) ---

	@Test
	@DisplayName("미인증 계정이 맞는 비밀번호로 로그인하면 403 AU006 이고 토큰이 없다")
	void 미인증_계정은_403_AU006() throws Exception {
		Account account = 미인증_계정을_만든다("au16-login-unverified@example.com");

		this.mockMvc.perform(login("au16-login-unverified@example.com", RAW_PASSWORD))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("AU006"))
				.andExpect(jsonPath("$.error.message").value(EMAIL_NOT_VERIFIED_MESSAGE))
				.andExpect(jsonPath("$.error.fieldErrors").isEmpty());

		assertThat(this.refreshTokenRepository.findByAccountId(account.getId())).isEmpty();
	}

	@Test
	@DisplayName("미인증 계정이어도 비밀번호가 틀리면 401 AU003 이다")
	void 미인증_계정의_틀린_비밀번호는_401_AU003() throws Exception {
		미인증_계정을_만든다("au16-login-unverified-wrong@example.com");

		this.mockMvc.perform(login("au16-login-unverified-wrong@example.com", "Other1!pw"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU003"))
				.andExpect(jsonPath("$.error.message").value(LOGIN_FAILED_MESSAGE));
	}

	/** 인증 확인({@code POST /accounts/email-verification/confirm})을 HTTP 로 거친 뒤의 로그인. */
	@Test
	@DisplayName("인증 확인을 거친 뒤에는 같은 계정이 200 으로 로그인된다")
	void 인증한_뒤_로그인은_200() throws Exception {
		Account account = 미인증_계정을_만든다("au16-login-verified@example.com");
		String token = AccountTokens.generate();
		this.accountTokenRepository.saveAndFlush(AccountToken.issue(account.getId(), TokenPurpose.EMAIL_VERIFICATION,
				AccountTokens.hash(token), Duration.ofHours(24), Clock.systemDefaultZone()));
		this.mockMvc.perform(login("au16-login-verified@example.com", RAW_PASSWORD))
				.andExpect(status().isForbidden());

		this.mockMvc.perform(post("/api/v1/accounts/email-verification/confirm")
						.contentType(MediaType.APPLICATION_JSON)
						.characterEncoding(StandardCharsets.UTF_8)
						.content("{\"token\": \"" + token + "\"}"))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(login("au16-login-verified@example.com", RAW_PASSWORD))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.accessToken").isNotEmpty());
	}

	/**
	 * {@code V6} 이 컬럼을 더하며 그때의 행 전부를 인증된 것으로 채웠다 — ADMIN seed 도 그 행이다
	 * (sp-docs/domain-model.md §2.1). 그래서 seed 는 인증 메일 없이 로그인한다.
	 *
	 * <p>테스트 프로파일의 seed 비밀번호는 BCrypt 해시가 아닌 placeholder 다(sp-docs/requirements/member.md §10.2) —
	 * 맞출 평문이 없다. 이 테스트 동안만 런타임에 인코딩한 값으로 바꾸고 끝나면 되돌린다. seed 행은 클래스 사이에
	 * 공유된다.
	 */
	@Test
	@DisplayName("V6 이 인증으로 채운 ADMIN seed 는 200 으로 로그인된다")
	void ADMIN_seed_는_로그인된다() throws Exception {
		Map<String, Object> seed = this.jdbcTemplate.queryForMap(
				"select id, password, email_verified_at from account where email = ?", ADMIN_EMAIL);
		assertThat(seed.get("email_verified_at")).as("V6 이 채웠다").isNotNull();
		Object seedId = seed.get("id");
		this.jdbcTemplate.update("update account set password = ? where id = ?",
				this.passwordEncoder.encode(RAW_PASSWORD), seedId);
		try {
			this.mockMvc.perform(login(ADMIN_EMAIL, RAW_PASSWORD))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.data.accessToken").isNotEmpty());
		} finally {
			this.jdbcTemplate.update("update account set password = ? where id = ?", seed.get("password"), seedId);
		}
	}

	// --- AU-18 로그인 잠금 (sp-docs/requirements/member.md §12, sp-docs/api-contract.md §2.1·§8.4) ---

	@Test
	@DisplayName("같은 이메일로 틀린 비밀번호를 연속으로 넣으면 넷째까지 401 AU003, 다섯째가 401 AU005 다")
	void 다섯째_실패는_401_AU005() throws Exception {
		String email = "au18-http-five@example.com";
		계정을_만든다(email);
		CLOCK.set(LOCK_NOW);

		네_번_실패한다(email);
		this.mockMvc.perform(login(email, WRONG_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("AU005"))
				.andExpect(jsonPath("$.error.message").value(LOGIN_LOCKED_MESSAGE))
				.andExpect(jsonPath("$.error.fieldErrors").isEmpty());
	}

	/**
	 * 완료 기준 「잠긴 경로의 응답이 비밀번호와 무관하게 같다(상태·본문)」. 본문을 통째로 비교한다 — 잠긴 동안 맞는 비밀번호의
	 * 응답이 갈리면 잠긴 동안에도 추측을 확인할 수 있다 (sp-docs/requirements/member.md §12.1).
	 */
	@Test
	@DisplayName("잠긴 동안 맞는 비밀번호는 401 AU005 이고 틀린 비밀번호의 응답과 상태·본문이 같다")
	void 잠긴_동안의_응답은_비밀번호와_무관하다() throws Exception {
		String email = "au18-http-locked@example.com";
		Account account = 계정을_만든다(email);
		CLOCK.set(LOCK_NOW);
		잠근다(email);

		CLOCK.set(LOCK_NOW.plusMinutes(1));
		MvcResult 맞는_비밀번호 = this.mockMvc.perform(login(email, RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("AU005"))
				.andExpect(jsonPath("$.error.message").value(LOGIN_LOCKED_MESSAGE))
				.andReturn();
		MvcResult 틀린_비밀번호 = this.mockMvc.perform(login(email, WRONG_PASSWORD)).andReturn();

		assertThat(맞는_비밀번호.getResponse().getStatus()).isEqualTo(틀린_비밀번호.getResponse().getStatus());
		assertThat(맞는_비밀번호.getResponse().getContentAsString(StandardCharsets.UTF_8))
				.isEqualTo(틀린_비밀번호.getResponse().getContentAsString(StandardCharsets.UTF_8));
		assertThat(this.refreshTokenRepository.findByAccountId(account.getId()))
				.as("맞는 비밀번호도 세션을 받지 않았다").isEmpty();
	}

	/** 잠금은 15분 뒤 풀린다 (sp-docs/requirements/member.md §12.1). 풀리는 시각의 경계는 {@code AuthServiceTest} 가 본다. */
	@Test
	@DisplayName("잠금 시각 1초 전에는 맞는 비밀번호도 401 AU005, 잠금 시각 너머에는 200 이다")
	void 잠금_시각_너머는_200() throws Exception {
		String email = "au18-http-unlock@example.com";
		계정을_만든다(email);
		CLOCK.set(LOCK_NOW);
		잠근다(email);

		CLOCK.set(LOCK_NOW.plusMinutes(15).minusSeconds(1));
		this.mockMvc.perform(login(email, RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU005"));

		CLOCK.set(LOCK_NOW.plusMinutes(15).plusSeconds(1));
		this.mockMvc.perform(login(email, RAW_PASSWORD))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.accessToken").isNotEmpty());
	}

	/**
	 * {@code AU005} 는 없는 이메일에도 똑같이 나온다 (sp-docs/api-contract.md §2.1) — 없는 이메일이 잠기지 않거나 잠긴 응답이
	 * 갈리면 잠금이 계정의 존재를 알려준다.
	 */
	@Test
	@DisplayName("없는 이메일로 연속 실패하면 다섯째가 401 AU005 이고, 있는 계정의 다섯째 응답과 상태·본문이 같다")
	void 없는_이메일도_다섯째에_잠긴다() throws Exception {
		String absent = "au18-http-nobody@example.com";
		String existing = "au18-http-somebody@example.com";
		계정을_만든다(existing);
		CLOCK.set(LOCK_NOW);

		네_번_실패한다(absent);
		MvcResult 없는_이메일 = this.mockMvc.perform(login(absent, RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU005"))
				.andReturn();
		네_번_실패한다(existing);
		MvcResult 있는_계정 = this.mockMvc.perform(login(existing, WRONG_PASSWORD)).andReturn();

		assertThat(없는_이메일.getResponse().getStatus()).isEqualTo(있는_계정.getResponse().getStatus());
		assertThat(없는_이메일.getResponse().getContentAsString(StandardCharsets.UTF_8))
				.isEqualTo(있는_계정.getResponse().getContentAsString(StandardCharsets.UTF_8));
	}

	/**
	 * 100자는 이메일의 최대 길이(sp-docs/requirements/member.md §2)이자 키 컬럼의 폭이다(§12.1). 넘으면 401 {@code AU003} 이고
	 * 세지 않는다(sp-docs/api-contract.md §2.1).
	 */
	@Test
	@DisplayName("이메일이 100자를 넘으면 401 AU003 이고 login_attempt 행이 생기지 않는다")
	void 백자를_넘는_이메일은_세지_않는다() throws Exception {
		String hundredOne = "a".repeat(89) + "@example.com";
		assertThat(hundredOne).as("픽스처").hasSize(101);
		CLOCK.set(LOCK_NOW);

		this.mockMvc.perform(login(hundredOne, RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU003"))
				.andExpect(jsonPath("$.error.message").value(LOGIN_FAILED_MESSAGE));

		assertThat(키들()).isEmpty();
	}

	/**
	 * 완료 기준 「{@code PATCH /me/password}·{@code DELETE /me} 의 {@code AU004} 는 세지 않는다」. 요청자는 이미 인증되어 있고
	 * 틀린 것은 본문의 값이다 (sp-docs/api-contract.md §2.2). 카운터에 실패 둘을 쌓아 둔 뒤 둘 다 보낸다 — 세면 3·4 가 된다.
	 */
	@Test
	@DisplayName("비밀번호 변경·탈퇴의 400 AU004 는 로그인 실패로 세지 않는다 — 카운터가 그대로다")
	void 비밀번호_변경과_탈퇴의_AU004_는_세지_않는다() throws Exception {
		String email = "au18-http-au004@example.com";
		계정을_만든다(email);
		IssuedTokens 세션 = 로그인한다(email);
		CLOCK.set(LOCK_NOW);
		for (int i = 0; i < 2; i++) {
			this.mockMvc.perform(login(email, WRONG_PASSWORD)).andExpect(jsonPath("$.error.code").value("AU003"));
		}
		Counter 쌓인_카운터 = new Counter(2, null, LOCK_NOW);
		assertThat(카운터(email)).as("픽스처").isEqualTo(쌓인_카운터);

		CLOCK.set(LOCK_NOW.plusMinutes(1));
		this.mockMvc.perform(patch("/api/v1/accounts/me/password")
						.header(HttpHeaders.AUTHORIZATION, "Bearer " + 세션.accessToken())
						.contentType(MediaType.APPLICATION_JSON)
						.characterEncoding(StandardCharsets.UTF_8)
						.content("{\"currentPassword\": \"" + WRONG_PASSWORD + "\", \"newPassword\": \"" + NEW_PASSWORD + "\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("AU004"));
		this.mockMvc.perform(delete("/api/v1/accounts/me")
						.header(HttpHeaders.AUTHORIZATION, "Bearer " + 세션.accessToken())
						.contentType(MediaType.APPLICATION_JSON)
						.characterEncoding(StandardCharsets.UTF_8)
						.content("{\"password\": \"" + WRONG_PASSWORD + "\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("AU004"));

		assertThat(카운터(email)).isEqualTo(쌓인_카운터);
	}

	/** AU-18 — 틀린 비밀번호로 네 번 실패한다. 넷 다 401 {@code AU003} 이다. */
	private void 네_번_실패한다(String email) throws Exception {
		for (int i = 1; i <= 4; i++) {
			this.mockMvc.perform(login(email, WRONG_PASSWORD))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.error.code").value("AU003"))
					.andExpect(jsonPath("$.error.message").value(LOGIN_FAILED_MESSAGE));
		}
	}

	/** AU-18 — 실제 경로로 잠근다. 네 번의 {@code AU003} 뒤 다섯째가 {@code AU005} 다. */
	private void 잠근다(String email) throws Exception {
		네_번_실패한다(email);
		this.mockMvc.perform(login(email, WRONG_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU005"));
	}

	/** AU-18 — 그 이메일의 커밋된 {@code login_attempt} 행. 행이 없으면 실패한다. JPA 를 거치지 않는다. */
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

	/** AU-18 — 커밋된 {@code login_attempt} 의 키 전부. */
	private List<String> 키들() {
		return this.jdbcTemplate.queryForList("select email_key from login_attempt order by email_key", String.class);
	}

	/** AU-18 — {@code login_attempt} 의 연속 실패 수·잠금 시각·마지막 갱신 시각. */
	private record Counter(int failedCount, LocalDateTime lockedUntil, LocalDateTime updatedAt) { }

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

	private static MockHttpServletRequestBuilder logout(String accessToken, String refreshToken) {
		return logoutWithBody(accessToken, "{\"refreshToken\": \"" + refreshToken + "\"}");
	}

	/** 로그아웃 본문은 로그아웃을 시작한 세션의 Refresh Token 이다 (sp-docs/api-contract.md §9.5). */
	private static MockHttpServletRequestBuilder logoutWithBody(String accessToken, String json) {
		return post("/api/v1/auth/logout")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

	/**
	 * 10초 전에 발급된 것으로 서명한 Refresh Token 으로 그 계정의 세션을 심는다. 재발급이 돌려주는
	 * 토큰과 문자열이 달라야 회전 전후를 가를 수 있다 (sp-docs/requirements/member.md §6.2).
	 */
	private String 저장된_세션을_만든다(Account account) {
		String token = TestTokens.signed(this.jwtEncoder, account.getId(), Role.USER,
				Instant.now().minusSeconds(10), Duration.ofDays(14));
		세션을_심는다(account, token, null);
		return token;
	}

	/**
	 * 그 계정의 행을 {@code token} 으로 바꿔 심는다. {@code previousToken} 이 있으면 그 값으로 행을
	 * 만든 뒤 조건부 UPDATE({@code rotate}) 로 회전시켜 직전 토큰이 되게 한다 — 직전 토큰을 쓰는
	 * 경로가 운영과 같다.
	 */
	private void 세션을_심는다(Account account, String token, String previousToken) {
		this.refreshTokenRepository.findByAccountId(account.getId())
				.ifPresent(this.refreshTokenRepository::delete);
		this.refreshTokenRepository.flush();

		LocalDateTime expiresAt = LocalDateTime.now().plusDays(14);
		this.refreshTokenRepository.saveAndFlush(RefreshToken.builder()
				.accountId(account.getId())
				.token(previousToken != null ? previousToken : token)
				.expiresAt(expiresAt)
				.build());
		if (previousToken != null) {
			Integer rotated = this.transactionTemplate.execute(status -> this.refreshTokenRepository.rotate(
					account.getId(), previousToken, token, expiresAt,
					LocalDateTime.now().truncatedTo(ChronoUnit.MICROS)));
			assertThat(rotated).isOne();
		}
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

	/**
	 * 인증된 계정. 프로필은 만들지 않는다 — auth 는 프로필을 소유하지 않는다.
	 *
	 * <p><b>AU-16 부터 인증을 채운다.</b> 미인증 계정의 맞는 비밀번호는 403 {@code AU006} 이므로
	 * (sp-docs/requirements/member.md §3 규칙 11) 로그인을 선행 상태로 쓰는 테스트들의 계정은 인증돼 있어야 한다.
	 */
	private Account 계정을_만든다(String email) {
		Account account = 미인증_계정을_만든다(email);
		account.markEmailVerified(Clock.systemDefaultZone());
		return this.accountRepository.saveAndFlush(account);
	}

	/** {@code email_verified_at} 이 NULL 인 계정 — AU-16 뒤에 가입한 계정이 인증 전에 그렇다. */
	private Account 미인증_계정을_만든다(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				// 런타임에 인코딩한다. 해시를 테스트 파일에 적으면 커밋되는 픽스처가 된다
				// (sp-docs/requirements/member.md §10.2)
				.password(this.passwordEncoder.encode(RAW_PASSWORD))
				.build());
	}

}
