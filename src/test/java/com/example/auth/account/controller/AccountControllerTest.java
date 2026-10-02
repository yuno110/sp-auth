package com.example.auth.account.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.support.TestRsaKeys;
import java.nio.charset.StandardCharsets;
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
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * sp-docs/plan/phase1.md §4 AU-05 의 "검증" 표 중 HTTP 쪽을 테스트로 옮긴 것이다.
 * 정본은 sp-docs/api-contract.md §2.2 §2.3 §9.1, 검증 규칙은
 * sp-docs/requirements/member.md §2 §2.1 이다.
 *
 * <p>인가 필터를 포함한 전 구간을 지난다 — {@code POST /api/v1/accounts} 와
 * {@code GET /accounts/check-email} 은 무인증이다 (sp-docs/security.md §5.1).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountControllerTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 테스트가 만든 것이 아니다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	private static final String EMAIL_MESSAGE = "올바른 이메일 형식이 아닙니다.";

	private static final String PASSWORD_MESSAGE =
			"비밀번호는 8~20자의 영문, 숫자, 특수문자 조합이어야 합니다.";

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	/**
	 * <b>seed 행은 남긴다.</b> H2 는 테스트 클래스 사이에 공유되므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 여기서 지우면
	 * {@code AdminSeedTest} 가 자기와 무관한 이유로 깨진다.
	 */
	@AfterEach
	void 정리() {
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

	private ResultActions checkEmail(String email) throws Exception {
		return this.mockMvc.perform(get("/api/v1/accounts/check-email").param("email", email));
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
