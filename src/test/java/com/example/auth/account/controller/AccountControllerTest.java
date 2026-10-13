package com.example.auth.account.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.TestRsaKeys;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * sp-docs/plan/phase1.md §4 AU-05·AU-08·AU-09·AU-10 의 "검증" 표 중 HTTP 쪽을 테스트로 옮긴
 * 것이다. 정본은 sp-docs/api-contract.md §2.2 §2.3 §9.1, 검증 규칙은
 * sp-docs/requirements/member.md §2 §2.1 이다.
 *
 * <p>인가 필터를 포함한 전 구간을 지난다 — {@code POST /api/v1/accounts} 와
 * {@code GET /accounts/check-email} 은 무인증이고 {@code /accounts/me*} 는 인증이다
 * (sp-docs/api-contract.md §2.2 의 "인증" 열).
 *
 * <p><b>경로별 인가 행렬은 {@code SecurityConfigTest} 가 본다.</b> 여기서 토큰 없는 접근을
 * 보는 것은 엔드포인트의 응답 본문까지 단언하는 경우뿐이다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountControllerTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	/** AU-08. sp-docs/api-contract.md §2.2 의 예시 본문이 쓰는 값이다. */
	private static final String NEW_PASSWORD = "NewPassw0rd!";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 테스트가 만든 것이 아니다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	private static final String EMAIL_MESSAGE = "올바른 이메일 형식이 아닙니다.";

	private static final String PASSWORD_MESSAGE =
			"비밀번호는 8~20자의 영문, 숫자, 특수문자 조합이어야 합니다.";

	/** sp-docs/api-contract.md §8.4 {@code AU004}. */
	private static final String PASSWORD_MISMATCH_MESSAGE = "현재 비밀번호가 일치하지 않습니다.";

	/**
	 * {@code currentPassword} 누락의 {@code fieldErrors} 메시지
	 * (sp-docs/api-contract.md §2.2). <b>존재 메시지이고 정책 메시지가 아니다.</b>
	 *
	 * <p>{@code PasswordChangeRequest} 의 상수를 참조하지 않는다 — 그쪽은 package-private 이고
	 * 이 테스트는 다른 패키지다. 위의 두 메시지 상수와 같은 방식이다.
	 */
	private static final String CURRENT_PASSWORD_MESSAGE = "현재 비밀번호를 입력해주세요.";

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private AccountRepository accountRepository;

	/** AU-08 — 비밀번호 변경이 지우는 대상 (sp-docs/requirements/member.md §3 규칙 4). */
	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	/**
	 * AU-10 — {@code sub} 가 가리키는 행이 없는 토큰을 만들기 위해서다. 발급은 계정 행을 보지
	 * 않으므로 로그인으로는 그 상태를 만들 수 없다.
	 */
	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	/**
	 * <b>seed 행은 남긴다.</b> H2 는 테스트 클래스 사이에 공유되므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 여기서 지우면
	 * {@code AdminSeedTest} 가 자기와 무관한 이유로 깨진다.
	 *
	 * <p>{@code fk_refresh_token_account} 가 있으므로 토큰을 먼저 지운다 — AU-08 의 테스트가
	 * 로그인으로 {@code refresh_token} 행을 만든다.
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
	@DisplayName("계정 생성은 201 과 {accountId, email} 을 반환한다")
	void 정상_생성() throws Exception {
		this.mockMvc.perform(createRequest("""
						{"email": "user@example.com", "password": "Passw0rd!"}"""))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.error").isEmpty())
				.andExpect(jsonPath("$.data.accountId").isNumber())
				.andExpect(jsonPath("$.data.email").value("user@example.com"));

		assertThat(this.accountRepository.existsByEmail("user@example.com")).isTrue();
	}

	@Test
	@DisplayName("응답 본문에 password·nickname 키가 없고 평문도 실리지 않는다")
	void 응답_본문() throws Exception {
		String body = this.mockMvc.perform(createRequest("""
						{"email": "body@example.com", "password": "Passw0rd!"}"""))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.data.password").doesNotExist())
				.andExpect(jsonPath("$.data.nickname").doesNotExist())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.as("비밀번호는 어떤 응답에도 넣지 않는다 (sp-docs/requirements/member.md §3 규칙 2)")
				.doesNotContain(RAW_PASSWORD)
				.doesNotContain("password")
				.doesNotContain("nickname");
	}

	@Test
	@DisplayName("중복 이메일은 409 AU002 다")
	void 중복_이메일() throws Exception {
		this.mockMvc.perform(createRequest("""
						{"email": "dup@example.com", "password": "Passw0rd!"}"""))
				.andExpect(status().isCreated());

		this.mockMvc.perform(createRequest("""
						{"email": "dup@example.com", "password": "Other1!pw"}"""))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("AU002"))
				.andExpect(jsonPath("$.error.message").value("이미 사용 중인 이메일입니다."));

		assertThat(테스트가_만든_계정_수()).isEqualTo(1);
	}

	/**
	 * {@code DataIntegrityViolationException} 이 그대로 올라가면 {@code GlobalExceptionHandler} 의
	 * 마지막 그물에 걸려 <b>500 {@code C005}</b> 가 된다. 재가입 거부가 실제로 409 {@code AU002}
	 * 로 나오는지 HTTP 경계에서 확인한다.
	 */
	@Test
	@DisplayName("탈퇴 계정의 이메일로 재가입하면 500 이 아니라 409 AU002 다")
	void 탈퇴_계정의_이메일로_재가입() throws Exception {
		탈퇴한_계정을_만든다("bye@example.com");

		this.mockMvc.perform(createRequest("""
						{"email": "bye@example.com", "password": "Passw0rd!"}"""))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.error.code").value("AU002"));

		assertThat(테스트가_만든_계정_수()).isEqualTo(1);
		assertThat(this.accountRepository.findByEmail("bye@example.com").orElseThrow().isDeleted())
				.isTrue();
	}

	@ParameterizedTest(name = "email = \"{0}\"")
	@ValueSource(strings = {
			"not-an-email",
			"",
			// 101자. 형식은 맞지만 최대 100자를 넘는다
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com"
	})
	@DisplayName("이메일 검증 실패는 400 C001 이다")
	void 이메일_검증(String email) throws Exception {
		this.mockMvc.perform(createRequest(
						"{\"email\": \"" + email + "\", \"password\": \"Passw0rd!\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("email"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(EMAIL_MESSAGE));

		assertThat(테스트가_만든_계정_수()).isZero();
	}

	/**
	 * 특수문자 집합은 sp-docs/requirements/member.md §2.1 이 ASCII 구두점으로 고정했다.
	 *
	 * <p>{@code 비밀번호1234} 가 핵심 케이스다 — 집합을 {@code [^A-Za-z0-9]} 로 읽으면 한글이
	 * 특수문자로 통과한다. 공백도 금지이므로 함께 본다.
	 */
	@ParameterizedTest(name = "password = \"{0}\"")
	@ValueSource(strings = {
			"Pw1!abc",                // 7자
			"Password1",              // 특수문자 없음
			"Passw0rd!Passw0rd!Pass", // 22자
			"password!",              // 숫자 없음
			"12345678!",              // 영문 없음
			"비밀번호1234",             // 한글은 특수문자가 아니다 (§2.1)
			"Passw0rd 1",             // 공백 금지 (§2.1)
			"Pass0rd가!"               // 허용 집합 밖의 문자가 섞였다
	})
	@DisplayName("비밀번호 검증 실패는 400 C001 이다")
	void 비밀번호_검증(String password) throws Exception {
		this.mockMvc.perform(createRequest(
						"{\"email\": \"pw@example.com\", \"password\": \"" + password + "\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("password"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(PASSWORD_MESSAGE));

		assertThat(테스트가_만든_계정_수()).isZero();
	}

	@ParameterizedTest(name = "password = \"{0}\"")
	@ValueSource(strings = {
			"Passw0rd!",            // 9자
			"aB3~aB3~",             // 8자 경계
			"aB3~aB3~aB3~aB3~aB3~"  // 20자 경계
	})
	@DisplayName("§2.1 집합을 지킨 비밀번호는 통과한다")
	void 비밀번호_경계(String password) throws Exception {
		this.mockMvc.perform(createRequest(
						"{\"email\": \"ok@example.com\", \"password\": \"" + password + "\"}"))
				.andExpect(status().isCreated());
	}

	@Test
	@DisplayName("검증 실패 응답에 사용자가 보낸 평문이 실리지 않는다")
	void 검증_실패_응답에_평문이_없다() throws Exception {
		String body = this.mockMvc.perform(createRequest("""
						{"email": "not-an-email", "password": "Passw0rd!"}"""))
				.andExpect(status().isBadRequest())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.as("rejectedValue 를 담지 않는다 (sp-docs/api-contract.md §7)")
				.doesNotContain(RAW_PASSWORD);
	}

	@Test
	@DisplayName("요청에 nickname 이 와도 무시되고 어디에도 저장되지 않는다")
	void 요청의_nickname_은_무시된다() throws Exception {
		String body = this.mockMvc.perform(createRequest("""
						{"email": "nick@example.com", "password": "Passw0rd!", "nickname": "홍길동"}"""))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.data.nickname").doesNotExist())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body).doesNotContain("홍길동").doesNotContain("nickname");

		// 저장된 행 전체를 컬럼 이름까지 열어서 본다. 닉네임은 member 소유이므로 account 에는
		// 담을 컬럼도, 담긴 값도 없어야 한다 (sp-docs/domain-model.md §2.1)
		Map<String, Object> row = this.jdbcTemplate
				.queryForList("select * from account where email = 'nick@example.com'").get(0);

		assertThat(row.keySet()).map(String::toLowerCase).doesNotContain("nickname");
		assertThat(row.values()).map(value -> String.valueOf(value)).doesNotContain("홍길동");
		assertThat(this.accountRepository.findByEmail("nick@example.com").orElseThrow().getRole())
				.isEqualTo(Role.USER);
	}

	@Test
	@DisplayName("요청 본문이 비어 있거나 깨져 있으면 400 C001 이다")
	void 읽을_수_없는_본문() throws Exception {
		for (String json : List.of("", "{", "{\"email\": }")) {
			this.mockMvc.perform(createRequest(json))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.error.code").value("C001"));
		}
	}

	// --- 이메일 중복 확인 (sp-docs/api-contract.md §2.3) ---

	@Test
	@DisplayName("쓰이지 않는 이메일은 available = true 다")
	void 중복_확인_미사용() throws Exception {
		checkEmail("free@example.com")
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.available").value(true))
				.andExpect(jsonPath("$.data.duplicated").doesNotExist());
	}

	@Test
	@DisplayName("쓰이고 있는 이메일은 available = false 다")
	void 중복_확인_사용중() throws Exception {
		this.mockMvc.perform(createRequest("""
						{"email": "taken@example.com", "password": "Passw0rd!"}"""))
				.andExpect(status().isCreated());

		checkEmail("taken@example.com")
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.available").value(false));
	}

	/** 행이 남고 UNIQUE 가 재사용을 막으므로 탈퇴해도 쓸 수 없다 (sp-docs/api-contract.md §2.3). */
	@Test
	@DisplayName("탈퇴한 계정의 이메일도 available = false 다")
	void 중복_확인_탈퇴_계정() throws Exception {
		탈퇴한_계정을_만든다("gone@example.com");

		checkEmail("gone@example.com")
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.available").value(false));
	}

	@Test
	@DisplayName("email 파라미터가 없으면 500 이 아니라 400 C001 이다")
	void 중복_확인_파라미터_누락() throws Exception {
		this.mockMvc.perform(get("/api/v1/accounts/check-email"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"));
	}

	/**
	 * 생성과 같은 이메일 규칙을 적용한다 (sp-docs/api-contract.md §2.3).
	 *
	 * <p>형식 오류에 {@code available: true} 를 돌려주면 <b>쓸 수 없는 값을 쓸 수 있다고 답하는
	 * 셈</b>이고, 클라이언트가 생성에서 400 을 받아 같은 판정을 두 번 하게 된다.
	 */
	@ParameterizedTest(name = "email = \"{0}\"")
	@ValueSource(strings = {
			"",             // 빈 문자열
			"not-an-email", // 형식 오류
			// 101자. 길이 초과
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com"
	})
	@DisplayName("중복 확인의 email 이 규칙에 맞지 않으면 400 C001 이다")
	void 중복_확인_파라미터_검증(String email) throws Exception {
		checkEmail(email)
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("email"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(EMAIL_MESSAGE))
				.andExpect(jsonPath("$.data").doesNotExist());
	}

	// --- 비밀번호 변경 (sp-docs/api-contract.md §2.2, sp-docs/plan/phase1.md §4 AU-08) ---

	@Test
	@DisplayName("비밀번호 변경은 204 와 빈 본문을 반환하고 refresh_token 행을 지운다")
	void 정상_변경() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("change@example.com");
		assertThat(this.refreshTokenRepository.findAll()).hasSize(1);

		String body = this.mockMvc
				.perform(changePassword(세션.accessToken(), 변경_본문(RAW_PASSWORD, NEW_PASSWORD)))
				.andExpect(status().isNoContent())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body).as("204 에는 본문을 담지 않는다").isEmpty();
		assertThat(this.refreshTokenRepository.findAll())
				.as("비밀번호 변경 시 Refresh Token 을 삭제한다 (sp-docs/security.md §7)")
				.isEmpty();
	}

	@Test
	@DisplayName("변경 후 새 비밀번호로 로그인되고 옛 비밀번호는 401 AU003 이다")
	void 변경_후_로그인() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("relogin@example.com");

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문(RAW_PASSWORD, NEW_PASSWORD)))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(loginRequest("relogin@example.com", NEW_PASSWORD))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.accessToken").isNotEmpty());

		this.mockMvc.perform(loginRequest("relogin@example.com", RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU003"));
	}

	/**
	 * <b>400 이다. 401 이 아니다</b> (sp-docs/api-contract.md §2.2) — 요청자는 이미 인증되어
	 * 있고, 틀린 것은 본문의 값이다.
	 */
	@Test
	@DisplayName("현재 비밀번호가 틀리면 400 AU004 다")
	void 현재_비밀번호_불일치() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("mismatch@example.com");

		String body = this.mockMvc
				.perform(changePassword(세션.accessToken(), 변경_본문("Other1!pw", NEW_PASSWORD)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("AU004"))
				.andExpect(jsonPath("$.error.message").value(PASSWORD_MISMATCH_MESSAGE))
				.andExpect(jsonPath("$.error.fieldErrors").isEmpty())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.as("비밀번호는 어떤 응답에도 넣지 않는다 (sp-docs/requirements/member.md §3 규칙 2)")
				.doesNotContain("Other1!pw")
				.doesNotContain(NEW_PASSWORD);

		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 변경은 Refresh Token 을 지우지 않는다")
				.hasSize(1);
		this.mockMvc.perform(loginRequest("mismatch@example.com", RAW_PASSWORD))
				.andExpect(status().isOk());
	}

	/**
	 * <b>검증표의 핵심 한 줄이다</b> — "{@code currentPassword} 가 형식 위반이고 값도 틀림 →
	 * 400 {@code AU004}. {@code C001} 이 아니다. 형식으로 가르지 않는다"
	 * (sp-docs/plan/phase1.md §4 AU-08).
	 *
	 * <p>{@code currentPassword} 에 비밀번호 규칙을 걸면 틀린 형식은 {@code C001},
	 * 형식은 맞지만 틀린 값은 {@code AU004} 가 되어 <b>응답이 갈린다</b>
	 * (sp-docs/api-contract.md §2.2).
	 */
	@ParameterizedTest(name = "currentPassword = \"{0}\"")
	@ValueSource(strings = {
			"short",        // 8자 미만, 숫자·특수문자 없음
			"비밀번호1234",   // 허용 집합 밖의 문자
			"Passw0rd 1"    // 공백 포함. §2.1 은 공백을 금지한다
	})
	@DisplayName("currentPassword 가 형식 위반이고 값도 틀리면 400 AU004 다")
	void currentPassword_는_형식으로_가르지_않는다(String currentPassword) throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("format@example.com");

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문(currentPassword, NEW_PASSWORD)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("AU004"))
				.andExpect(jsonPath("$.error.message").value(PASSWORD_MISMATCH_MESSAGE));

		this.mockMvc.perform(loginRequest("format@example.com", RAW_PASSWORD))
				.andExpect(status().isOk());
	}

	/**
	 * <b>누락은 {@code AU004} 가 아니라 {@code C001} 이다</b> (sp-docs/api-contract.md §2.2).
	 * 금지되는 것은 형식 검증({@code @Pattern})이고 빈 값 검사({@code @NotBlank})는 요구된다 —
	 * 빈 값은 어떤 정책에서도 올바른 비밀번호가 아니므로 정책 변경으로 잠길 사용자가 없다.
	 *
	 * <p>{@code AU004} 의 메시지("현재 비밀번호가 일치하지 않습니다")는 <b>아무것도 보내지 않은
	 * 요청에는 거짓이다.</b> {@code DELETE /accounts/me} 도 같은 코드를 쓴다
	 * (sp-docs/plan/phase1.md §4 AU-09).
	 *
	 * <p>네 입력을 함께 보는 것이 요점이다 — 넷이 같은 코드로 수렴하는지는 하나씩 보면
	 * 드러나지 않는다.
	 */
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"{\"newPassword\": \"" + NEW_PASSWORD + "\"}",
			"{\"currentPassword\": null, \"newPassword\": \"" + NEW_PASSWORD + "\"}",
			"{\"currentPassword\": \"\", \"newPassword\": \"" + NEW_PASSWORD + "\"}",
			"{\"currentPassword\": \"   \", \"newPassword\": \"" + NEW_PASSWORD + "\"}"
	})
	@DisplayName("currentPassword 누락·null·빈 값은 400 C001 이고 fieldErrors 에 currentPassword 다")
	void currentPassword_누락(String json) throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("absent@example.com");

		this.mockMvc.perform(changePassword(세션.accessToken(), json))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors.length()").value(1))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("currentPassword"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message")
						.value(CURRENT_PASSWORD_MESSAGE));

		assertThat(this.refreshTokenRepository.findAll())
				.as("검증 실패는 컨트롤러 앞에서 끝난다 — 토큰을 지우지 않는다")
				.hasSize(1);
		this.mockMvc.perform(loginRequest("absent@example.com", RAW_PASSWORD))
				.andExpect(status().isOk());
	}

	/**
	 * <b>존재 메시지이고 정책 메시지가 아니다</b> (sp-docs/api-contract.md §2.2).
	 * {@code newPassword} 쪽과 메시지가 갈리는 것이 요점이다 — 정책 설명("8~20자의 영문,
	 * 숫자, 특수문자 조합")을 돌려주면 사용자가 자기 비밀번호의 형식이 틀렸다고 읽는다.
	 */
	@Test
	@DisplayName("currentPassword 누락과 newPassword 형식 오류의 메시지가 다르다")
	void 두_필드의_메시지가_갈린다() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("messages@example.com");

		this.mockMvc.perform(changePassword(세션.accessToken(),
						"{\"newPassword\": \"" + NEW_PASSWORD + "\"}"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(CURRENT_PASSWORD_MESSAGE));

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문(RAW_PASSWORD, "short")))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(PASSWORD_MESSAGE));

		assertThat(CURRENT_PASSWORD_MESSAGE).isNotEqualTo(PASSWORD_MESSAGE);
	}

	/**
	 * <b>둘 다 틀리면 {@code C001} 이다</b> (sp-docs/api-contract.md §2.2) — Bean Validation
	 * 이 컨트롤러 앞에서 돌기 때문이고, 그 순서는 현재 비밀번호에 대해 아무것도 알려주지 않으므로
	 * 그대로 둔다.
	 */
	@Test
	@DisplayName("새 비밀번호 형식 오류와 현재 비밀번호 불일치가 동시면 400 C001 이다")
	void 둘_다_틀리면_C001() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("both@example.com");

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문("Other1!pw", "short")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("newPassword"));
	}

	/**
	 * <b>탈퇴한 계정의 토큰으로는 바꿀 수 없다 — 404 {@code AU001}</b>
	 * (sp-docs/api-contract.md §2.2). Access Token 이 탈퇴 후에도 만료까지 통과하므로
	 * (sp-docs/security.md §5.3) 실제로 도달 가능한 경로다.
	 *
	 * <p><b>{@code updated_at} 까지 단언하는 것이 이 검사의 실질이다.</b> 권한 상승을 막는 것이
	 * 아니라(탈퇴 계정은 새 세션을 만들 수 없다) 닫힌 행의 자격증명이 덮이는 것과 <b>탈퇴 시점의
	 * 유일한 흔적이 지워지는 것</b>을 막는다 — {@code account} 에 {@code deleted_at} 컬럼이 없다.
	 *
	 * <p>탈퇴는 엔티티로 직접 만든다 — {@code DELETE /accounts/me} 로 만들지 않는 이유는
	 * {@link #탈퇴시킨다(String)} 에 적었다. <b>탈퇴한 계정에 대한 결론은 엔드포인트마다
	 * 다르다</b> — 그쪽은 멱등이라 204 다. 어느 엔드포인트가 무엇으로 끝나는지는
	 * sp-docs/api-contract.md §2.2 의 표가 정한다.
	 */
	@Test
	@DisplayName("탈퇴한 계정의 토큰으로 변경하면 404 AU001 이고 password·updated_at 이 그대로다")
	void 탈퇴한_계정() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("withdrawn@example.com");
		Long id = 탈퇴시킨다("withdrawn@example.com");

		// 탈퇴 자체가 updated_at 을 갱신하므로 탈퇴 "후"의 값을 기준으로 잡는다
		String password = 컬럼(id, "password");
		String updatedAt = 컬럼(id, "updated_at");

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문(RAW_PASSWORD, NEW_PASSWORD)))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("AU001"))
				.andExpect(jsonPath("$.error.message").value("계정을 찾을 수 없습니다."));

		assertThat(컬럼(id, "password"))
				.as("닫힌 행의 자격증명이 덮이지 않는다")
				.isEqualTo(password);
		assertThat(컬럼(id, "updated_at"))
				.as("탈퇴 시점의 유일한 흔적이 지워지지 않는다 (deleted_at 컬럼이 없다)")
				.isEqualTo(updatedAt);
	}

	@ParameterizedTest(name = "newPassword = \"{0}\"")
	@ValueSource(strings = {
			"Pw1!abc",      // 7자
			"Password1",    // 특수문자 없음
			"password!",    // 숫자 없음
			"비밀번호1234",   // 한글은 특수문자가 아니다 (§2.1)
			"Passw0rd 1"    // 공백 금지 (§2.1)
	})
	@DisplayName("새 비밀번호 형식 오류는 400 C001 이고 fieldErrors 에 newPassword 가 담긴다")
	void 새_비밀번호_검증(String newPassword) throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("newpw@example.com");

		String body = this.mockMvc
				.perform(changePassword(세션.accessToken(), 변경_본문(RAW_PASSWORD, newPassword)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("newPassword"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(PASSWORD_MESSAGE))
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.as("rejectedValue 를 담지 않는다 (sp-docs/api-contract.md §7)")
				.doesNotContain(newPassword)
				.doesNotContain(RAW_PASSWORD);

		assertThat(this.refreshTokenRepository.findAll())
				.as("검증 실패는 컨트롤러 앞에서 끝난다 — 토큰을 지우지 않는다")
				.hasSize(1);
	}

	/**
	 * <b>새 비밀번호가 현재와 같아도 거부하지 않는다</b> (sp-docs/api-contract.md §2.2).
	 * 비교에 BCrypt 가 한 번 더 들고, RefreshToken 은 어차피 삭제되어 세션이 끊긴다.
	 */
	@Test
	@DisplayName("새 비밀번호가 현재와 같아도 204 다")
	void 현재와_같은_새_비밀번호() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("same@example.com");

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문(RAW_PASSWORD, RAW_PASSWORD)))
				.andExpect(status().isNoContent());

		assertThat(this.refreshTokenRepository.findAll()).isEmpty();
		this.mockMvc.perform(loginRequest("same@example.com", RAW_PASSWORD))
				.andExpect(status().isOk());
	}

	/**
	 * <b>변경 전에 발급된 Access Token 이 만료까지 계속 통과한다</b>
	 * (sp-docs/security.md §5.3). RefreshToken 을 지워 새 세션은 막지만 이미 발급된 Access
	 * Token 에는 서버 상태가 없다 — "비밀번호를 바꿨으니 안전하다"는 <b>최대 31분 뒤부터 참</b>이다.
	 *
	 * <p>즉시 차단은 1차 범위 밖이고 탈퇴·권한 회수와 같은 포기 목록에 있다. <b>이 테스트가
	 * 그 창을 문서화한다</b> — 나중에 블랙리스트를 넣으면 여기서 깨지고, 그때 정본이 함께 바뀐다.
	 *
	 * <p>보호 경로는 변경 엔드포인트 자신을 쓴다. 옛 토큰으로 한 번 더 바꿀 수 있다는 것이
	 * 곧 "통과한다"다.
	 */
	@Test
	@DisplayName("변경 후에도 기존 Access Token 으로 보호 경로를 통과한다")
	void 변경_후_기존_Access_Token() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("window@example.com");

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문(RAW_PASSWORD, NEW_PASSWORD)))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문(NEW_PASSWORD, "Third1!pw")))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(loginRequest("window@example.com", "Third1!pw"))
				.andExpect(status().isOk());
	}

	/** 저장값이 삭제됐으므로 재발급은 실패한다 (sp-docs/security.md §5.3). */
	@Test
	@DisplayName("변경 후 기존 Refresh Token 으로 재발급하면 401 A002 다")
	void 변경_후_기존_Refresh_Token() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("reissue@example.com");

		this.mockMvc.perform(changePassword(세션.accessToken(), 변경_본문(RAW_PASSWORD, NEW_PASSWORD)))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(post("/api/v1/auth/reissue")
						.contentType(MediaType.APPLICATION_JSON)
						.characterEncoding(StandardCharsets.UTF_8)
						.content("{\"refreshToken\": \"" + 세션.refreshToken() + "\"}"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A002"));

		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 재발급이 행을 다시 만들지 않는다")
				.isEmpty();
	}

	// --- 계정 탈퇴 (sp-docs/api-contract.md §2.2, sp-docs/plan/phase1.md §4 AU-09) ---

	/**
	 * <b>204 와 빈 본문</b>이고 <b>행은 남는다</b> (sp-docs/api-contract.md §2.2).
	 * {@code Account.withdraw()} 의 Soft Delete 이므로 {@code uk_account_email} 이 탈퇴한
	 * 이메일의 재사용을 계속 막는다 (sp-docs/requirements/member.md §3 규칙 1).
	 */
	@Test
	@DisplayName("탈퇴는 204 와 빈 본문을 반환하고 deleted = true, 행 존재, 토큰 삭제다")
	void 정상_탈퇴() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("withdraw@example.com");
		assertThat(this.refreshTokenRepository.findAll()).hasSize(1);

		String body = this.mockMvc.perform(withdraw(세션.accessToken(), 탈퇴_본문(RAW_PASSWORD)))
				.andExpect(status().isNoContent())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body).as("204 에는 본문을 담지 않는다").isEmpty();
		assertThat(this.accountRepository.findByEmail("withdraw@example.com").orElseThrow().isDeleted())
				.as("행 삭제가 아니다 (sp-docs/plan/phase1.md §4 AU-09 완료 기준)")
				.isTrue();
		assertThat(테스트가_만든_계정_수()).isEqualTo(1);
		assertThat(this.refreshTokenRepository.findAll())
				.as("탈퇴 시 Refresh Token 을 삭제한다 (sp-docs/requirements/member.md §3 규칙 4)")
				.isEmpty();
	}

	/**
	 * <b>누락은 {@code AU004} 가 아니라 {@code C001} 이다</b> (sp-docs/api-contract.md §2.2).
	 * 금지되는 것은 형식 검증({@code @Pattern})이고 빈 값 검사({@code @NotBlank})는 요구된다.
	 * {@code AU004} 의 메시지는 <b>아무것도 보내지 않은 요청에는 거짓이다</b> —
	 * {@code PATCH /me/password} 와 같은 성질의 필드를 같은 코드로 처리한다 (§2.2).
	 *
	 * <p>네 입력을 함께 보는 것이 요점이다. 넷이 같은 코드로 수렴하는지는 하나씩 보면
	 * 드러나지 않는다.
	 */
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"{}",
			"{\"password\": null}",
			"{\"password\": \"\"}",
			"{\"password\": \"   \"}"
	})
	@DisplayName("탈퇴 요청에 password 가 없으면 400 C001 이고 fieldErrors 에 password 다")
	void 탈퇴_비밀번호_누락(String json) throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("absent-withdraw@example.com");

		this.mockMvc.perform(withdraw(세션.accessToken(), json))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors.length()").value(1))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("password"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(CURRENT_PASSWORD_MESSAGE));

		assertThat(탈퇴_여부("absent-withdraw@example.com"))
				.as("검증 실패는 컨트롤러 앞에서 끝난다 — 계정을 닫지 않는다")
				.isFalse();
		assertThat(this.refreshTokenRepository.findAll()).hasSize(1);
	}

	/**
	 * <b>400 이다. 401 이 아니다</b> (sp-docs/api-contract.md §2.2) — 요청자는 이미 인증되어
	 * 있고 틀린 것은 본문의 값이다. <b>{@code deleted} 는 그대로 {@code false} 다.</b>
	 */
	@Test
	@DisplayName("탈퇴 요청의 비밀번호가 틀리면 400 AU004 이고 deleted 가 그대로 false 다")
	void 탈퇴_비밀번호_불일치() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("wrongpw@example.com");

		String body = this.mockMvc.perform(withdraw(세션.accessToken(), 탈퇴_본문("Other1!pw")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("AU004"))
				.andExpect(jsonPath("$.error.message").value(PASSWORD_MISMATCH_MESSAGE))
				.andExpect(jsonPath("$.error.fieldErrors").isEmpty())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.as("비밀번호는 어떤 응답에도 넣지 않는다 (sp-docs/requirements/member.md §3 규칙 2)")
				.doesNotContain("Other1!pw");

		assertThat(탈퇴_여부("wrongpw@example.com")).isFalse();
		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 탈퇴는 Refresh Token 을 지우지 않는다")
				.hasSize(1);
		this.mockMvc.perform(loginRequest("wrongpw@example.com", RAW_PASSWORD))
				.andExpect(status().isOk());
	}

	/** 로그인이 {@code deleted} 를 검사한다 (sp-docs/requirements/member.md §3 규칙 5). */
	@Test
	@DisplayName("탈퇴 후 로그인하면 401 AU003 이다")
	void 탈퇴_후_로그인() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("relogin-withdraw@example.com");

		this.mockMvc.perform(withdraw(세션.accessToken(), 탈퇴_본문(RAW_PASSWORD)))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(loginRequest("relogin-withdraw@example.com", RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU003"));
	}

	/**
	 * 저장값이 삭제됐으므로 재발급은 실패한다. 거부는 {@code A002} 다 — 사유를 구분해
	 * 내보내지 않는다 (sp-docs/api-contract.md §8.5, AU-07).
	 */
	@Test
	@DisplayName("탈퇴 후 기존 Refresh Token 으로 재발급하면 401 A002 다")
	void 탈퇴_후_재발급() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("reissue-withdraw@example.com");

		this.mockMvc.perform(withdraw(세션.accessToken(), 탈퇴_본문(RAW_PASSWORD)))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(post("/api/v1/auth/reissue")
						.contentType(MediaType.APPLICATION_JSON)
						.characterEncoding(StandardCharsets.UTF_8)
						.content("{\"refreshToken\": \"" + 세션.refreshToken() + "\"}"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A002"));

		assertThat(this.refreshTokenRepository.findAll())
				.as("거부된 재발급이 행을 다시 만들지 않는다")
				.isEmpty();
	}

	/**
	 * <b>멱등이다 — 이미 탈퇴했으면 204 이고 아무것도 바꾸지 않는다</b>
	 * (MR-10, sp-docs/api-contract.md §2.2). 두 번째 호출이 같은 Access Token 으로 가는
	 * 것이 정상 경로다 — 그 토큰은 탈퇴 후에도 만료까지 통과한다 (sp-docs/security.md §5.3).
	 *
	 * <p><b>{@code updated_at} 까지 단언하는 것이 이 멱등의 실질이다.</b> 닫힌 행에 쓰기가
	 * 닿으면 탈퇴 시점의 유일한 흔적이 지워진다 — {@code account} 에 {@code deleted_at}
	 * 컬럼이 없다 (sp-docs/domain-model.md §2.1).
	 */
	@Test
	@DisplayName("이미 탈퇴한 계정에 다시 탈퇴하면 204 이고 updated_at 이 그대로다")
	void 이미_탈퇴한_계정_재호출() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("idempotent@example.com");

		this.mockMvc.perform(withdraw(세션.accessToken(), 탈퇴_본문(RAW_PASSWORD)))
				.andExpect(status().isNoContent());

		Long id = this.accountRepository.findByEmail("idempotent@example.com").orElseThrow().getId();
		String updatedAt = 컬럼(id, "updated_at");

		this.mockMvc.perform(withdraw(세션.accessToken(), 탈퇴_본문(RAW_PASSWORD)))
				.andExpect(status().isNoContent());

		assertThat(컬럼(id, "updated_at"))
				.as("아무것도 바꾸지 않는다 (sp-docs/api-contract.md §2.2)")
				.isEqualTo(updatedAt);
		assertThat(탈퇴_여부("idempotent@example.com")).isTrue();
	}

	/**
	 * <b>{@code deleted} 검사가 비밀번호 비교보다 먼저다</b> (sp-docs/api-contract.md §2.2).
	 * {@code PATCH /me/password} 와 <b>같은 순서이고 결론만 반대다</b> — 그쪽은 404 로 거부하고
	 * ({@link #탈퇴한_계정()}) 이쪽은 204 로 통과한다. 재확인이 요구되는 것(MR-10)은 <b>계정을
	 * 닫는 행위</b>에 대한 것이고, 이미 닫힌 계정에는 보호할 상태가 없다.
	 */
	@Test
	@DisplayName("이미 탈퇴한 계정은 비밀번호가 틀려도 204 다")
	void 이미_탈퇴한_계정_재호출_비밀번호_틀림() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("idem-wrongpw@example.com");

		this.mockMvc.perform(withdraw(세션.accessToken(), 탈퇴_본문(RAW_PASSWORD)))
				.andExpect(status().isNoContent());

		Long id = this.accountRepository.findByEmail("idem-wrongpw@example.com").orElseThrow().getId();
		String updatedAt = 컬럼(id, "updated_at");

		String body = this.mockMvc.perform(withdraw(세션.accessToken(), 탈퇴_본문("Other1!pw")))
				.andExpect(status().isNoContent())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body).as("AU004 가 아니다 — 검사가 비교보다 먼저다").isEmpty();
		assertThat(컬럼(id, "updated_at")).isEqualTo(updatedAt);
	}

	// --- AU-10 내 계정 조회 (sp-docs/plan/phase1.md §4 AU-10) ---

	/**
	 * MR-07 이 두 서비스로 갈라진 절반이다 (sp-docs/requirements/member.md §5). 닉네임 쪽은
	 * member 의 {@code GET /api/v1/members/me} 이고, 둘 다 필요한 화면은 클라이언트가 두 번
	 * 호출한다.
	 */
	@Test
	@DisplayName("내 계정 조회는 200 과 {email, createdAt} 을 반환한다")
	void 내_계정_조회() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("me@example.com");
		LocalDateTime 가입일 =
				this.accountRepository.findByEmail("me@example.com").orElseThrow().getCreatedAt();

		String body = this.mockMvc.perform(getMe(세션.accessToken()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.error").isEmpty())
				.andExpect(jsonPath("$.data.email").value("me@example.com"))
				.andExpect(jsonPath("$.data.createdAt").exists())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		String createdAt = JsonPath.read(body, "$.data.createdAt");
		assertThat(LocalDateTime.parse(createdAt))
				.as("가입일은 account.created_at 이다 (sp-docs/api-contract.md §2.2)")
				.isEqualTo(가입일);
	}

	/**
	 * <b>키 집합 자체를 고정한다.</b> {@code password}·{@code nickname} 이 없다는 단언만으로는
	 * 부족하다 — 다른 필드를 더해도 통과하기 때문이다. {@code accountId} 도 넣지 않는다
	 * (sp-docs/api-contract.md §2.2).
	 *
	 * <p>필드가 늘면 여기서 깨지고, 그때 정본이 함께 바뀐다. <b>더하는 것은 호환되고 빼는 것은
	 * 아니므로</b> 늘릴 요구가 생기면 정본을 먼저 고친다.
	 */
	@Test
	@DisplayName("응답 data 의 키 집합이 email·createdAt 으로 고정된다")
	void 조회_응답_키_집합() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("keys@example.com");

		String body = this.mockMvc.perform(getMe(세션.accessToken()))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		Map<String, Object> data = JsonPath.read(body, "$.data");
		assertThat(data)
				.as("accountId 도 없다 (sp-docs/api-contract.md §2.2)")
				.containsOnlyKeys("email", "createdAt");
	}

	/** 평문도 해시도 어떤 응답에 넣지 않는다 (sp-docs/requirements/member.md §3 규칙 2). */
	@Test
	@DisplayName("조회 응답에 password·nickname 키가 없고 해시도 실리지 않는다")
	void 조회_응답_본문() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("body-me@example.com");
		Long id = this.accountRepository.findByEmail("body-me@example.com").orElseThrow().getId();
		String 저장된_해시 = 컬럼(id, "password");

		String body = this.mockMvc.perform(getMe(세션.accessToken()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.password").doesNotExist())
				.andExpect(jsonPath("$.data.nickname").doesNotExist())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.doesNotContain(RAW_PASSWORD)
				.doesNotContain(저장된_해시)
				.doesNotContain("password")
				.doesNotContain("nickname");
	}

	/**
	 * 토큰 없는 접근은 401 {@code A001} 이다. 경로별 인가 행렬은 {@code SecurityConfigTest} 가
	 * 보고, 여기서는 <b>이 엔드포인트가 인증 없이 계정 데이터를 내보내지 않는지</b>를 본다 —
	 * 둘은 깨지는 이유가 다르다.
	 */
	@Test
	@DisplayName("토큰 없이 조회하면 401 A001 이고 본문에 계정 데이터가 없다")
	void 토큰_없이_조회() throws Exception {
		계정과_세션을_만든다("noauth@example.com");

		String body = this.mockMvc.perform(get("/api/v1/accounts/me"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("A001"))
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body).doesNotContain("noauth@example.com");
	}

	/**
	 * 조회 대상은 검증된 토큰의 {@code sub} 가 정한다 (sp-docs/security.md §4). 파라미터·본문의
	 * 식별자를 읽는 지점이 없으므로 타인의 {@code accountId} 는 무시된다.
	 *
	 * <p>남의 계정으로 seed 행을 쓴다 — 실재하는 다른 행이어야 "무시됐다"가 반증 가능해진다.
	 * 파라미터를 신뢰하면 그 계정의 이메일이 돌아온다.
	 */
	@Test
	@DisplayName("타인의 accountId 를 파라미터·본문으로 보내도 자기 정보만 반환한다")
	void 타인의_accountId_는_무시된다() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("mine@example.com");
		Long 남의_id = this.accountRepository.findByEmail(ADMIN_EMAIL).orElseThrow().getId();

		this.mockMvc.perform(get("/api/v1/accounts/me")
						.header(HttpHeaders.AUTHORIZATION, "Bearer " + 세션.accessToken())
						.param("accountId", String.valueOf(남의_id))
						.contentType(MediaType.APPLICATION_JSON)
						.characterEncoding(StandardCharsets.UTF_8)
						.content("{\"accountId\": " + 남의_id
								+ ", \"email\": \"" + ADMIN_EMAIL + "\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.email").value("mine@example.com"));
	}

	/**
	 * <b>탈퇴한 계정은 API 관점에서 없는 계정이다</b> (sp-docs/api-contract.md §2.2 의 표).
	 * Access Token 은 탈퇴 후에도 만료까지 통과하므로(sp-docs/security.md §5.3) 도달 가능한
	 * 경로다. {@code DELETE /accounts/me} 만 그 경우에 204 이고(멱등이 요구사항이다) 조회는
	 * 404 다.
	 *
	 * <p>탈퇴는 엔티티로 직접 만든다 — 이유는 {@link #탈퇴시킨다(String)} 에 적었다.
	 */
	@Test
	@DisplayName("탈퇴한 계정의 토큰으로 조회하면 404 AU001 이다")
	void 탈퇴한_계정의_토큰으로_조회() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("gone@example.com");
		탈퇴시킨다("gone@example.com");

		String body = this.mockMvc.perform(getMe(세션.accessToken()))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("AU001"))
				.andExpect(jsonPath("$.error.message").value("계정을 찾을 수 없습니다."))
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body)
				.as("거부된 조회는 계정 데이터를 내보내지 않는다")
				.doesNotContain("gone@example.com");
	}

	/**
	 * {@code sub} 가 가리키는 행이 없을 때도 404 {@code AU001} 이다 — <b>탈퇴와 같은 코드다</b>
	 * (sp-docs/api-contract.md §2.2 의 표). 서명·만료는 유효하므로 요청이 컨트롤러에 닿는다.
	 *
	 * <p>토큰은 실제 발급 경로로 만든다 (sp-docs/conventions.md §9.2). 그 경로는 계정 행을 보지
	 * 않으므로 없는 {@code sub} 로도 서명할 수 있고, 만료 폭을 픽스처에 적을 필요가 없다.
	 */
	@Test
	@DisplayName("sub 가 가리키는 행이 없으면 404 AU001 이다")
	void 행이_없는_sub로_조회() throws Exception {
		String accessToken = this.jwtTokenProvider.issue(999_999L, Role.USER).accessToken();

		this.mockMvc.perform(getMe(accessToken))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.error.code").value("AU001"));
	}

	/**
	 * <b>오프셋을 표기하지 않는다</b> (sp-docs/api-contract.md §2.2, sp-docs/tech-stack.md §6).
	 * 타입을 {@code OffsetDateTime} 으로 바꾸거나 오프셋을 포함한 포맷을 지정하면 끝에 표기가
	 * 붙어 여기서 잡힌다.
	 *
	 * <p><b>초 미만 자리는 실행 환경이 정한다.</b> MySQL {@code DATETIME} 은 초 단위이고
	 * (sp-docs/domain-model.md §1.1) 테스트의 H2 는 소수부를 보존한다. 정본이 고정한 것은
	 * 오프셋 미표기이므로 소수부는 선택으로 둔다.
	 */
	@Test
	@DisplayName("createdAt 에 오프셋 표기가 없다")
	void createdAt_형식() throws Exception {
		IssuedTokens 세션 = 계정과_세션을_만든다("iso@example.com");

		String body = this.mockMvc.perform(getMe(세션.accessToken()))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		String createdAt = JsonPath.read(body, "$.data.createdAt");
		assertThat(createdAt)
				.as("Z 도 +09:00 도 붙지 않는다 (sp-docs/tech-stack.md §6)")
				.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?");
	}

	private ResultActions checkEmail(String email) throws Exception {
		return this.mockMvc.perform(get("/api/v1/accounts/check-email").param("email", email));
	}

	/** 계정을 만들고 로그인한다. 둘 다 실제 엔드포인트를 지나므로 픽스처에 해시를 적지 않는다. */
	private IssuedTokens 계정과_세션을_만든다(String email) throws Exception {
		this.mockMvc.perform(createRequest(
						"{\"email\": \"" + email + "\", \"password\": \"" + RAW_PASSWORD + "\"}"))
				.andExpect(status().isCreated());

		String body = this.mockMvc.perform(loginRequest(email, RAW_PASSWORD))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		return new IssuedTokens(
				JsonPath.read(body, "$.data.accessToken"),
				JsonPath.read(body, "$.data.refreshToken"));
	}

	/** 로그인 응답에서 꺼낸 두 토큰. */
	private record IssuedTokens(String accessToken, String refreshToken) { }

	private static MockHttpServletRequestBuilder loginRequest(String email, String password) {
		return post("/api/v1/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content("{\"email\": \"" + email + "\", \"password\": \"" + password + "\"}");
	}

	/** 내 계정 조회 요청. 본문도 파라미터도 없다 — 대상은 토큰의 {@code sub} 가 정한다. */
	private static MockHttpServletRequestBuilder getMe(String accessToken) {
		return get("/api/v1/accounts/me")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
	}

	private static MockHttpServletRequestBuilder changePassword(String accessToken, String json) {
		return patch("/api/v1/accounts/me/password")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

	private static String 변경_본문(String currentPassword, String newPassword) {
		return "{\"currentPassword\": \"" + currentPassword + "\", "
				+ "\"newPassword\": \"" + newPassword + "\"}";
	}

	/**
	 * 탈퇴 요청. <b>본문이 있는 {@code DELETE} 다</b> — 비밀번호 재확인이 요구되고(MR-10),
	 * member 는 비밀번호를 갖지 않으므로 이 검증은 여기에만 있을 수 있다
	 * (sp-docs/requirements/member.md §8).
	 */
	private static MockHttpServletRequestBuilder withdraw(String accessToken, String json) {
		return delete("/api/v1/accounts/me")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

	/** 필드 이름은 {@code password} 다. {@code currentPassword} 가 아니다 (§2.2). */
	private static String 탈퇴_본문(String password) {
		return "{\"password\": \"" + password + "\"}";
	}

	/** 커밋된 {@code deleted}. {@code 컬럼} 은 {@code String} 으로 읽어 불리언에 쓰지 않는다. */
	private boolean 탈퇴_여부(String email) {
		return this.accountRepository.findByEmail(email).orElseThrow().isDeleted();
	}

	/**
	 * 이미 있는 계정을 탈퇴 상태로 엔티티로 직접 바꾼다. <b>{@code DELETE /accounts/me} 로
	 * 바꾸지 않는 것이 의도다</b> — 이 헬퍼를 쓰는 쪽은 탈퇴를 <b>선행 상태로만</b> 전제하고
	 * 탈퇴 자체를 검사하지 않는다. 선행 상태를 {@code DELETE /accounts/me} 로 만들면 그 테스트가
	 * 탈퇴 엔드포인트의 동작에 의존하게 된다. 그쪽은 같은 트랜잭션에서 Refresh Token 행까지
	 * 지우므로 "탈퇴했는데 토큰 행이 남아 있는" 상태를 만들 수도 없다 — 그 상태를 요구하는 쪽은
	 * {@code AccountServiceTest} 의 같은 헬퍼다.
	 */
	private Long 탈퇴시킨다(String email) {
		Account account = this.accountRepository.findByEmail(email).orElseThrow();
		account.withdraw();
		return this.accountRepository.saveAndFlush(account).getId();
	}

	/** 커밋된 행의 한 컬럼. JPA 를 거치지 않는다 — 영속성 컨텍스트가 아니라 DB 를 봐야 한다. */
	private String 컬럼(Long accountId, String column) {
		return this.jdbcTemplate.queryForObject(
				"select " + column + " from account where id = ?", String.class, accountId);
	}

	private void 탈퇴한_계정을_만든다(String email) {
		Account account = this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				// 해시가 아니다. 이 테스트는 비밀번호를 맞추지 않으므로 맞출 평문도 없다.
				// BCrypt 모양을 쓰지 않는다 (sp-docs/requirements/member.md §10.2)
				.password("test-not-a-hash-withdrawn-account")
				.build());
		account.withdraw();
		this.accountRepository.saveAndFlush(account);
	}

	/** seed 행을 뺀 수. 절대 개수로 단언하면 seed 유무에 따라 결과가 바뀐다. */
	private long 테스트가_만든_계정_수() {
		return this.accountRepository.findAll().stream()
				.filter(account -> !ADMIN_EMAIL.equals(account.getEmail()))
				.count();
	}

	private static MockHttpServletRequestBuilder createRequest(String json) {
		return post("/api/v1/accounts")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

}
