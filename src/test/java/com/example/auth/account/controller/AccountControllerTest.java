package com.example.auth.account.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
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
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.global.config.MailExecutorConfig;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.InMemoryMailer;
import com.example.auth.support.MailExecutorDrain;
import com.example.auth.support.MutableClock;
import com.example.auth.support.TestRsaKeys;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
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

	/** AU-16. sp-docs/api-contract.md §8.4 {@code AU007}. */
	private static final String INVALID_LINK_TOKEN_MESSAGE = "링크가 유효하지 않거나 만료되었습니다.";

	/**
	 * AU-16 — {@code token} 누락의 {@code fieldErrors} 메시지. 존재 메시지다({@code TokenConfirmRequest}).
	 * {@link #CURRENT_PASSWORD_MESSAGE} 와 같은 이유로 상수를 참조하지 않는다.
	 */
	private static final String TOKEN_MESSAGE = "토큰을 입력해주세요.";

	/** AU-16 — 202 의 본문. 계정의 상태와 상관없이 이것 하나다 (sp-docs/api-contract.md §2.4). */
	private static final String ACCEPTED_BODY = "{\"success\":true,\"data\":null,\"error\":null}";

	/**
	 * AU-16 — {@code application-test.yml} 의 {@code mail.frontend-base-url}. 링크의 기준 주소는 이 설정에서만 온다
	 * (sp-docs/security.md §12). 요청에는 이것과 다른 {@code Host} 를 싣는다.
	 */
	private static final String FRONTEND_BASE_URL = "http://localhost:3000";

	/** AU-16 — 요청에 싣는 다른 {@code Host}. 링크에 나오면 안 된다. */
	private static final String FORGED_HOST = "attacker.example.test";

	private static final Pattern VERIFY_LINK =
			Pattern.compile(Pattern.quote(FRONTEND_BASE_URL + "/verify-email#token=") + "(\\S+)");

	/** AU-17 — 재설정 메일의 링크 (sp-docs/requirements/member.md §11.5). */
	private static final Pattern RESET_LINK =
			Pattern.compile(Pattern.quote(FRONTEND_BASE_URL + "/reset-password#token=") + "(\\S+)");

	/** AU-16 — 인증·만료를 정확한 시각으로 보려고 시계를 멈추는 시각. */
	private static final LocalDateTime NOW = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	/** AU-16 — 앱 시계를 바꿔 끼운다. 고정하지 않은 테스트에서는 시스템 시계다 ({@link MutableClock}). */
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

	/** AU-16 — 인증 링크 토큰. 가입·재발송이 다른 스레드에서 만들고, 확인이 사용 처리한다. */
	@Autowired
	private AccountTokenRepository accountTokenRepository;

	/** AU-16 — 시험용 발송기 ({@code TestMailConfig}). 보낸 메일을 모은다. */
	@Autowired
	private InMemoryMailer inMemoryMailer;

	/** AU-16 — 발급 작업과 발송이 도는 실행기. 정리와 「더 보낸 메일이 없다」 가 이것이 비기를 기다린다. */
	@Autowired
	@Qualifier(MailExecutorConfig.MAIL_EXECUTOR)
	private ThreadPoolTaskExecutor mailExecutor;

	/**
	 * <b>seed 행은 남긴다.</b> H2 는 테스트 클래스 사이에 공유되므로
	 * ({@code DB_CLOSE_DELAY=-1}, sp-docs/tech-stack.md §5.3) 여기서 지우면
	 * {@code AdminSeedTest} 가 자기와 무관한 이유로 깨진다.
	 *
	 * <p>{@code fk_refresh_token_account} 가 있으므로 토큰을 먼저 지운다 — AU-08 의 테스트가
	 * 로그인으로 {@code refresh_token} 행을 만든다.
	 *
	 * <p><b>AU-16 부터 가입이 다른 스레드에서 {@code account_token} 행과 메일을 만든다.</b> 그 작업이 끝나기를 먼저
	 * 기다리고({@link MailExecutorDrain}) 메일을 버린 뒤 그 행을 지운다 — 남기면 계정 삭제가
	 * {@code fk_account_token_account} 에 걸린다.
	 *
	 * <p>AU-17 의 테스트가 {@code login_attempt} 행을 심는다. 그 테이블은 계정을 참조하지 않으므로 지우는 순서와 상관없다.
	 */
	@AfterEach
	void 정리() {
		CLOCK.reset();
		MailExecutorDrain.drain(this.mailExecutor);
		this.inMemoryMailer.clear();
		this.accountTokenRepository.deleteAllInBatch();
		this.refreshTokenRepository.deleteAll();
		this.refreshTokenRepository.flush();
		this.jdbcTemplate.update("delete from login_attempt");
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
	 * <p><b>소수부는 선택으로 둔다.</b> 감사가 만든 값에는 소수부가 없지만({@code D-11} 이
	 * 초로 잘랐다, sp-docs/api-contract.md §4.3) <b>SQL 로 심은 행에는 남을 수 있다</b> —
	 * auth 의 ADMIN seed 가 {@code NOW()} 로 들어가고 그 행은 감사를 거치지 않는다.
	 * 정본이 고정한 것은 오프셋 미표기뿐이다.
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

	/**
	 * 가입하고 로그인한다. 둘 다 실제 엔드포인트를 지나므로 픽스처에 해시를 적지 않는다.
	 *
	 * <p><b>AU-16 부터 그 사이에 인증을 채운다</b> — 미인증 계정의 로그인은 403 {@code AU006} 이다
	 * (sp-docs/requirements/member.md §3 규칙 11). 이 헬퍼를 쓰는 테스트는 세션을 선행 상태로만 전제하므로 인증을
	 * 엔터티로 채운다. 가입 메일의 링크로 인증하는 흐름은 {@link #확인_정상()} 이 본다.
	 */
	private IssuedTokens 계정과_세션을_만든다(String email) throws Exception {
		this.mockMvc.perform(createRequest(
						"{\"email\": \"" + email + "\", \"password\": \"" + RAW_PASSWORD + "\"}"))
				.andExpect(status().isCreated());
		인증을_채운다(email, LocalDateTime.now(CLOCK));

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

	// --- AU-16 이메일 인증 — 가입 뒤 발급·재발송·확인 (sp-docs/plan/phase2-auth-member.md AU-16 의 검증 표) ---

	@Test
	@DisplayName("가입은 201 이고 커밋 뒤 인증 메일이 한 통 간다 — 요청의 Host 가 달라도 링크의 기준 주소는 설정값이다")
	void 가입은_인증_메일을_보낸다() throws Exception {
		this.mockMvc.perform(createRequest("{\"email\": \"au16-signup@example.com\", \"password\": \""
								+ RAW_PASSWORD + "\"}")
						.header(HttpHeaders.HOST, FORGED_HOST))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.data.email").value("au16-signup@example.com"));

		InMemoryMailer.Sent sent = this.inMemoryMailer.next(Duration.ofSeconds(5));
		assertThat(sent.mail().to()).isEqualTo("au16-signup@example.com");
		assertThat(sent.mail().purpose()).isEqualTo(TokenPurpose.EMAIL_VERIFICATION.name());
		assertThat(sent.mail().text()).doesNotContain(FORGED_HOST);
		assertThat(링크의_토큰(sent)).isNotBlank();
		더_보낸_메일이_없다();
	}

	@Test
	@DisplayName("재발송은 계정이 없다·탈퇴했다·인증됐다·아니다 모두 202 와 같은 본문이고, 메일은 미인증일 때만 간다")
	void 재발송은_언제나_202() throws Exception {
		미인증_계정을_만든다("au16-resend-unverified@example.com");
		Long verified = 미인증_계정을_만든다("au16-resend-verified@example.com");
		인증을_채운다("au16-resend-verified@example.com", NOW);
		탈퇴한_계정을_만든다("au16-resend-withdrawn@example.com");

		List<String> bodies = new ArrayList<>();
		for (String email : List.of("au16-resend-none@example.com", "au16-resend-withdrawn@example.com",
				"au16-resend-verified@example.com", "au16-resend-unverified@example.com")) {
			bodies.add(this.mockMvc.perform(resend("{\"email\": \"" + email + "\"}").header(HttpHeaders.HOST, FORGED_HOST))
					.andExpect(status().isAccepted())
					.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8));
		}

		assertThat(bodies).as("202 가 계정의 상태를 말하지 않는다 (sp-docs/api-contract.md §2.4)")
				.containsOnly(ACCEPTED_BODY).hasSize(4);
		InMemoryMailer.Sent sent = this.inMemoryMailer.next(Duration.ofSeconds(5));
		assertThat(sent.mail().to()).isEqualTo("au16-resend-unverified@example.com");
		assertThat(sent.mail().text()).doesNotContain(FORGED_HOST);
		assertThat(링크의_토큰(sent)).isNotBlank();
		더_보낸_메일이_없다();
		assertThat(this.accountTokenRepository.findAll()).extracting(AccountToken::getAccountId)
				.as("인증된 계정에는 토큰도 없다").doesNotContain(verified);
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"{}",
			"{\"email\": null}",
			"{\"email\": \"\"}",
			"{\"email\": \"not-an-email\"}",
			// 101자. 형식은 맞고(라벨 셋이 31자씩) 최대 100자만 넘는다
			"{\"email\": \"a@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com\"}"
	})
	@DisplayName("재발송의 email 이 생성과 같은 규칙을 어기면 400 C001 이고 fieldErrors 에 email 이다")
	void 재발송_형식_위반(String json) throws Exception {
		this.mockMvc.perform(resend(json))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors.length()").value(1))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("email"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(EMAIL_MESSAGE));
	}

	@Test
	@DisplayName("재발송의 email 은 100자까지 받는다 — 길이 경계의 안쪽은 202 다")
	void 재발송_100자() throws Exception {
		String email = "a@" + "b".repeat(31) + "." + "b".repeat(31) + "." + "b".repeat(30) + ".com";
		assertThat(email).hasSize(100);

		this.mockMvc.perform(resend("{\"email\": \"" + email + "\"}"))
				.andExpect(status().isAccepted());
	}

	@Test
	@DisplayName("확인 — 가입 메일의 링크 토큰으로 204, 본문이 없고 email_verified_at 이 지금 시각으로 채워진다. 토큰을 주지 않는다")
	void 확인_정상() throws Exception {
		CLOCK.set(NOW);
		this.mockMvc.perform(createRequest("{\"email\": \"au16-confirm@example.com\", \"password\": \""
						+ RAW_PASSWORD + "\"}"))
				.andExpect(status().isCreated());
		String token = 링크의_토큰(this.inMemoryMailer.next(Duration.ofSeconds(5)));
		Long id = this.accountRepository.findByEmail("au16-confirm@example.com").orElseThrow().getId();
		CLOCK.set(NOW.plusHours(1));

		String body = this.mockMvc.perform(confirm("{\"token\": \"" + token + "\"}"))
				.andExpect(status().isNoContent())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body).as("본문이 없다 — Access·Refresh 를 주지 않는다").isEmpty();
		assertThat(인증_시각(id)).isEqualTo(NOW.plusHours(1));
		assertThat(this.refreshTokenRepository.findByAccountId(id)).as("세션을 만들지 않는다").isEmpty();
	}

	@Test
	@DisplayName("확인 — 같은 토큰을 두 번 보내면 둘째가 400 AU007 이다")
	void 확인_같은_토큰_두_번() throws Exception {
		Long id = 미인증_계정을_만든다("au16-twice@example.com");
		String token = 토큰을_심는다(id, TokenPurpose.EMAIL_VERIFICATION);

		this.mockMvc.perform(confirm("{\"token\": \"" + token + "\"}"))
				.andExpect(status().isNoContent());
		링크_토큰_오류다(this.mockMvc.perform(confirm("{\"token\": \"" + token + "\"}")));
	}

	/**
	 * 수명은 발급 작업이 정한 24시간이다 (sp-docs/requirements/member.md §11.1). 사용 처리가 {@code expires_at > now} 를
	 * 보므로 발급 뒤 24시간에서 1초 모자라면 받고, 꼭 24시간이면 받지 않는다. 토큰은 재발송의 실제 발급으로 만든다 —
	 * 수명을 이 테스트가 다시 적지 않는다.
	 */
	@Test
	@DisplayName("확인 — 수명 경계: 발급 뒤 24시간에서 1초 모자라면 204, 꼭 24시간이면 400 AU007 이다")
	void 확인_수명_경계() throws Exception {
		CLOCK.set(NOW);
		Long inside = 미인증_계정을_만든다("au16-expiry-inside@example.com");
		Long boundary = 미인증_계정을_만든다("au16-expiry-boundary@example.com");
		String insideToken = 재발송하고_토큰을_꺼낸다("au16-expiry-inside@example.com");
		String boundaryToken = 재발송하고_토큰을_꺼낸다("au16-expiry-boundary@example.com");

		CLOCK.set(NOW.plusHours(24).minusSeconds(1));
		this.mockMvc.perform(confirm("{\"token\": \"" + insideToken + "\"}"))
				.andExpect(status().isNoContent());

		CLOCK.set(NOW.plusHours(24));
		링크_토큰_오류다(this.mockMvc.perform(confirm("{\"token\": \"" + boundaryToken + "\"}")));

		assertThat(인증_시각(inside)).isEqualTo(NOW.plusHours(24).minusSeconds(1));
		assertThat(인증_시각(boundary)).isNull();
		assertThat(사용_시각(boundaryToken)).isNull();
	}

	@Test
	@DisplayName("확인 — 재설정 목적의 토큰은 400 AU007 이다. 그 토큰은 쓰이지 않는다")
	void 확인_재설정_목적의_토큰() throws Exception {
		Long id = 미인증_계정을_만든다("au16-reset-purpose@example.com");
		String token = 토큰을_심는다(id, TokenPurpose.PASSWORD_RESET);

		링크_토큰_오류다(this.mockMvc.perform(confirm("{\"token\": \"" + token + "\"}")));

		assertThat(인증_시각(id)).isNull();
		assertThat(사용_시각(token)).isNull();
	}

	@Test
	@DisplayName("확인 — 탈퇴한 계정은 400 AU007 이다. email_verified_at 은 그대로이고 토큰의 사용 처리도 되돌려진다")
	void 확인_탈퇴한_계정() throws Exception {
		Long id = 미인증_계정을_만든다("au16-withdrawn@example.com");
		String token = 토큰을_심는다(id, TokenPurpose.EMAIL_VERIFICATION);
		탈퇴시킨다("au16-withdrawn@example.com");

		링크_토큰_오류다(this.mockMvc.perform(confirm("{\"token\": \"" + token + "\"}")));

		assertThat(인증_시각(id)).isNull();
		assertThat(사용_시각(token)).as("사용 처리가 확인의 트랜잭션과 함께 되돌려진다").isNull();
	}

	/**
	 * 탈퇴 검사가 「이미 인증됐으면 그대로 둔다」 보다 먼저다 (sp-docs/requirements/member.md §11.2 의 2 와 3) — 인증된
	 * 계정이어도 탈퇴했으면 204 가 아니다. 인증된 계정에도 살아 있는 인증 토큰이 있을 수 있다: 같은 계정·같은 목적의 발급
	 * 둘이 겹치면 둘 다 남을 수 있고(§11.1), 하나로 인증해도 다른 하나는 남는다.
	 */
	@Test
	@DisplayName("확인 — 이미 인증된 계정도 탈퇴했으면 400 AU007 이다. email_verified_at 은 그대로이고 토큰의 사용 처리도 되돌려진다")
	void 확인_인증된_뒤_탈퇴한_계정() throws Exception {
		CLOCK.set(NOW);
		Long id = 미인증_계정을_만든다("au16-verified-withdrawn@example.com");
		인증을_채운다("au16-verified-withdrawn@example.com", NOW.minusDays(1));
		String token = 토큰을_심는다(id, TokenPurpose.EMAIL_VERIFICATION);
		탈퇴시킨다("au16-verified-withdrawn@example.com");

		링크_토큰_오류다(this.mockMvc.perform(confirm("{\"token\": \"" + token + "\"}")));

		assertThat(인증_시각(id)).as("처음 인증한 시각이 그대로다").isEqualTo(NOW.minusDays(1));
		assertThat(사용_시각(token)).as("사용 처리가 확인의 트랜잭션과 함께 되돌려진다").isNull();
	}

	@Test
	@DisplayName("확인 — 이미 인증된 계정은 204 이고 처음 인증한 시각이 남는다")
	void 확인_이미_인증된_계정() throws Exception {
		CLOCK.set(NOW);
		Long id = 미인증_계정을_만든다("au16-already@example.com");
		인증을_채운다("au16-already@example.com", NOW.minusDays(1));
		String token = 토큰을_심는다(id, TokenPurpose.EMAIL_VERIFICATION);

		this.mockMvc.perform(confirm("{\"token\": \"" + token + "\"}"))
				.andExpect(status().isNoContent());

		assertThat(인증_시각(id)).isEqualTo(NOW.minusDays(1));
		assertThat(사용_시각(token)).as("토큰은 쓰였다").isEqualTo(NOW);
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"{}",
			"{\"token\": null}",
			"{\"token\": \"\"}",
			"{\"token\": \"   \"}"
	})
	@DisplayName("확인 — token 누락·null·빈 값은 400 C001 이고 fieldErrors 에 token 이다")
	void 확인_token_누락(String json) throws Exception {
		this.mockMvc.perform(confirm(json))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors.length()").value(1))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("token"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(TOKEN_MESSAGE));
	}

	/**
	 * 형식 검증을 걸지 않는다 (sp-docs/api-contract.md §2.4) — 길이·문자 집합이 틀린 토큰은 맞지 않는 토큰이고 400
	 * {@code C001} 이 아니라 {@code AU007} 이다. 발급하는 토큰은 43자의 base64url 이다(AU-15).
	 */
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"a",
			// 42자·44자 — 발급하는 길이의 바로 안팎
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			// 43자지만 base64url 밖의 문자
			"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
			"토큰",
			"has space"
	})
	@DisplayName("확인 — 길이·문자가 틀린 token 은 C001 이 아니라 400 AU007 이다")
	void 확인_형식이_틀린_token(String token) throws Exception {
		링크_토큰_오류다(this.mockMvc.perform(confirm("{\"token\": \"" + token + "\"}")));
	}

	@Test
	@DisplayName("확인 — 아주 긴 token 도 400 AU007 이다")
	void 확인_아주_긴_token() throws Exception {
		링크_토큰_오류다(this.mockMvc.perform(confirm("{\"token\": \"" + "A".repeat(10_000) + "\"}")));
	}

	// --- AU-16 도우미 ---

	private static MockHttpServletRequestBuilder resend(String json) {
		return post("/api/v1/accounts/email-verification")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

	private static MockHttpServletRequestBuilder confirm(String json) {
		return post("/api/v1/accounts/email-verification/confirm")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

	/** 400 {@code AU007} — 없음·만료·사용됨·목적 다름·탈퇴 계정이 이 하나다 (sp-docs/requirements/member.md §11.1). */
	private static void 링크_토큰_오류다(ResultActions result) throws Exception {
		result.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("AU007"))
				.andExpect(jsonPath("$.error.message").value(INVALID_LINK_TOKEN_MESSAGE))
				.andExpect(jsonPath("$.error.fieldErrors").isEmpty());
	}

	/** 링크의 기준 주소가 설정값인지 보고 토큰을 꺼낸다. */
	private static String 링크의_토큰(InMemoryMailer.Sent sent) {
		Matcher matcher = VERIFY_LINK.matcher(sent.mail().text());
		assertThat(matcher.find()).as("본문의 링크가 설정의 기준 주소로 시작한다: " + VERIFY_LINK.pattern()).isTrue();
		return matcher.group(1);
	}

	/** 발송 실행기가 빈 뒤에 남은 메일이 없다. 빈 뒤에는 새 메일이 올 곳이 없으므로 기다리지 않고 본다. */
	private void 더_보낸_메일이_없다() {
		MailExecutorDrain.drain(this.mailExecutor);
		assertThatThrownBy(() -> this.inMemoryMailer.next(Duration.ZERO))
				.as("더 보낸 메일이 없다")
				.isInstanceOf(AssertionError.class);
	}

	/** 재발송을 보내고 그 메일의 토큰을 꺼낸다. 계정은 활성·미인증이어야 한다. */
	private String 재발송하고_토큰을_꺼낸다(String email) throws Exception {
		this.mockMvc.perform(resend("{\"email\": \"" + email + "\"}"))
				.andExpect(status().isAccepted());
		InMemoryMailer.Sent sent = this.inMemoryMailer.next(Duration.ofSeconds(5));
		assertThat(sent.mail().to()).isEqualTo(email);
		return 링크의_토큰(sent);
	}

	/**
	 * 가입({@code POST /accounts})을 거치지 않은 미인증 계정. 가입은 다른 스레드에서 토큰과 메일을 만들어, 이 테스트가
	 * 심은 토큰을 지울 수 있다(같은 계정·목적의 앞 토큰 지우기). 비밀번호는 해시가 아니다 — 이 계정으로 로그인하지 않는다.
	 */
	private Long 미인증_계정을_만든다(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				.password("test-not-a-hash-au16")
				.build()).getId();
	}

	/**
	 * 그 계정의 토큰 행을 앱 시계의 지금으로 심고 원문을 돌려준다. 수명은 목적과 상관없이 하루로 둔다 — 이 헬퍼로 만료를
	 * 보지 않는다. 만료는 {@link #확인_수명_경계()} 가 실제 발급으로 본다.
	 */
	private String 토큰을_심는다(Long accountId, TokenPurpose purpose) {
		String token = AccountTokens.generate();
		this.accountTokenRepository.saveAndFlush(AccountToken.issue(accountId, purpose, AccountTokens.hash(token),
				Duration.ofDays(1), CLOCK));
		return token;
	}

	private void 인증을_채운다(String email, LocalDateTime verifiedAt) {
		Account account = this.accountRepository.findByEmail(email).orElseThrow();
		MutableClock at = new MutableClock();
		at.set(verifiedAt);
		account.markEmailVerified(at);
		this.accountRepository.saveAndFlush(account);
	}

	/** 커밋된 {@code email_verified_at}. JPA 를 거치지 않는다. */
	private LocalDateTime 인증_시각(Long accountId) {
		return this.jdbcTemplate.queryForObject(
				"select email_verified_at from account where id = ?", LocalDateTime.class, accountId);
	}

	/** 커밋된 {@code used_at}. 원문이 아니라 해시로 찾는다. */
	private LocalDateTime 사용_시각(String token) {
		return this.jdbcTemplate.queryForObject(
				"select used_at from account_token where token_hash = ?", LocalDateTime.class, AccountTokens.hash(token));
	}

	// --- AU-17 비밀번호 재설정 — 요청·확인 (sp-docs/plan/phase2-auth-member.md AU-17 의 검증 표) ---

	/**
	 * 응답은 계정의 상태를 말하지 않는다 (sp-docs/api-contract.md §2.4). 메일은 활성 계정에만 가고 인증 여부를 보지 않는다
	 * (sp-docs/requirements/member.md §11.3 의 표).
	 */
	@Test
	@DisplayName("재설정 요청은 계정이 없다·탈퇴했다·미인증·인증 모두 202 와 같은 본문이고, 메일은 활성 계정에만 간다")
	void 재설정_요청은_언제나_202() throws Exception {
		Long unverified = 미인증_계정을_만든다("au17-request-unverified@example.com");
		Long verified = 미인증_계정을_만든다("au17-request-verified@example.com");
		인증을_채운다("au17-request-verified@example.com", NOW);
		탈퇴한_계정을_만든다("au17-request-withdrawn@example.com");
		// 탈퇴한 계정을 인증된 상태로 둔다 — 발송 판정이 탈퇴가 아니라 인증 여부를 보면 메일이 나가 그 단언이 실패한다
		인증을_채운다("au17-request-withdrawn@example.com", NOW);

		List<String> bodies = new ArrayList<>();
		for (String email : List.of("au17-request-none@example.com", "au17-request-withdrawn@example.com",
				"au17-request-unverified@example.com", "au17-request-verified@example.com")) {
			bodies.add(this.mockMvc.perform(resetRequest("{\"email\": \"" + email + "\"}"))
					.andExpect(status().isAccepted())
					.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8));
		}

		assertThat(bodies).as("202 가 계정의 상태를 말하지 않는다 (sp-docs/api-contract.md §2.4)")
				.containsOnly(ACCEPTED_BODY).hasSize(4);
		List<InMemoryMailer.Sent> sent = List.of(
				this.inMemoryMailer.next(Duration.ofSeconds(5)), this.inMemoryMailer.next(Duration.ofSeconds(5)));
		assertThat(sent).extracting(each -> each.mail().to())
				.containsExactlyInAnyOrder("au17-request-unverified@example.com", "au17-request-verified@example.com");
		assertThat(sent).allSatisfy(each -> {
			assertThat(each.mail().purpose()).isEqualTo(TokenPurpose.PASSWORD_RESET.name());
			assertThat(재설정_링크의_토큰(each)).isNotBlank();
		});
		더_보낸_메일이_없다();
		assertThat(this.accountTokenRepository.findAll())
				.extracting(AccountToken::getAccountId, AccountToken::getPurpose)
				.as("활성 계정 둘에 재설정 토큰이 있고, 탈퇴한 계정에는 없다")
				.containsExactlyInAnyOrder(
						tuple(unverified, TokenPurpose.PASSWORD_RESET), tuple(verified, TokenPurpose.PASSWORD_RESET));
	}

	/** 링크의 기준 주소는 설정이고 요청의 {@code Host} 로 만들지 않는다 (sp-docs/requirements/member.md §11.5). */
	@Test
	@DisplayName("재설정 요청에 다른 Host 를 실어도 메일 링크의 기준 주소는 설정값이다")
	void 재설정_메일의_링크는_설정의_기준_주소다() throws Exception {
		미인증_계정을_만든다("au17-host@example.com");

		this.mockMvc.perform(resetRequest("{\"email\": \"au17-host@example.com\"}").header(HttpHeaders.HOST, FORGED_HOST))
				.andExpect(status().isAccepted());

		InMemoryMailer.Sent sent = this.inMemoryMailer.next(Duration.ofSeconds(5));
		assertThat(sent.mail().to()).isEqualTo("au17-host@example.com");
		assertThat(sent.mail().text()).doesNotContain(FORGED_HOST);
		assertThat(재설정_링크의_토큰(sent)).isNotBlank();
		더_보낸_메일이_없다();
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"{}",
			"{\"email\": null}",
			"{\"email\": \"\"}",
			"{\"email\": \"not-an-email\"}",
			// 101자. 형식은 맞고(라벨 셋이 31자씩) 최대 100자만 넘는다
			"{\"email\": \"a@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.com\"}"
	})
	@DisplayName("재설정 요청의 email 이 생성과 같은 규칙을 어기면 400 C001 이고 fieldErrors 에 email 이다")
	void 재설정_요청_형식_위반(String json) throws Exception {
		this.mockMvc.perform(resetRequest(json))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors.length()").value(1))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("email"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(EMAIL_MESSAGE));
	}

	/**
	 * 요청만으로는 기존 세션·잠금·비밀번호가 바뀌지 않는다 — 바뀌는 것은 확인 때다 (sp-docs/requirements/member.md §11.3).
	 * 발급 작업은 커밋한 뒤에 메일을 보내므로 메일이 온 뒤에 보는 값은 그 작업이 끝난 뒤의 값이다.
	 */
	@Test
	@DisplayName("재설정 요청만으로는 세션·잠금·비밀번호가 바뀌지 않는다 — 메일이 나간 뒤에도 그대로다")
	void 재설정_요청만으로는_바뀌지_않는다() throws Exception {
		CLOCK.set(NOW);
		IssuedTokens 세션 = 재설정할_계정과_세션을_만든다("au17-request-only@example.com");
		Long id = this.accountRepository.findByEmail("au17-request-only@example.com").orElseThrow().getId();
		잠긴_행을_심는다("au17-request-only@example.com", 5, NOW.plusMinutes(15));
		String password = 컬럼(id, "password");

		재설정을_요청하고_토큰을_꺼낸다("au17-request-only@example.com");

		assertThat(컬럼(id, "password")).as("비밀번호").isEqualTo(password);
		assertThat(this.refreshTokenRepository.findByAccountId(id))
				.map(RefreshToken::getToken).as("세션").contains(세션.refreshToken());
		assertThat(잠금_행("au17-request-only@example.com")).as("잠금")
				.isEqualTo(new LockState(5, NOW.plusMinutes(15)));
	}

	/**
	 * 토큰은 재설정 요청의 실제 발급으로 만든다 — 메일의 링크에서 꺼낸다. 이 계정은 인증됐고 잠금 행이 없다 — 행이 없는 키의
	 * 해제는 0행이고 실패가 아니다 ({@code LoginAttemptRepository#reset}).
	 */
	@Test
	@DisplayName("확인 — 재설정 메일의 링크 토큰으로 204, 본문이 없다. 새 비밀번호로 로그인 200, 옛 비밀번호는 401 AU003 이다")
	void 재설정_확인_정상() throws Exception {
		CLOCK.set(NOW);
		재설정할_계정과_세션을_만든다("au17-confirm@example.com");
		Long id = this.accountRepository.findByEmail("au17-confirm@example.com").orElseThrow().getId();
		String token = 재설정을_요청하고_토큰을_꺼낸다("au17-confirm@example.com");
		CLOCK.set(NOW.plusMinutes(10));

		String body = this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD)))
				.andExpect(status().isNoContent())
				.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

		assertThat(body).as("본문이 없다 — Access·Refresh 를 주지 않는다").isEmpty();
		assertThat(사용_시각(token)).isEqualTo(NOW.plusMinutes(10));
		assertThat(this.refreshTokenRepository.findByAccountId(id)).as("세션을 만들지 않고, 있던 세션은 지웠다").isEmpty();
		assertThat(인증_시각(id)).as("이미 인증된 계정 — 처음 인증한 시각이 남는다").isEqualTo(NOW);

		this.mockMvc.perform(loginRequest("au17-confirm@example.com", RAW_PASSWORD))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("AU003"));
		this.mockMvc.perform(loginRequest("au17-confirm@example.com", NEW_PASSWORD))
				.andExpect(status().isOk());
	}

	/** 그 계정의 {@code refresh_token} 행을 지웠으므로 재발급은 실패한다. 다른 계정의 세션은 그대로다. */
	@Test
	@DisplayName("확인 뒤 옛 Refresh Token 으로 재발급하면 401 A002 다 — 다른 계정의 세션은 그대로다")
	void 재설정_확인_뒤_옛_Refresh_Token() throws Exception {
		IssuedTokens 세션 = 재설정할_계정과_세션을_만든다("au17-old-refresh@example.com");
		IssuedTokens 남의_세션 = 재설정할_계정과_세션을_만든다("au17-bystander-session@example.com");
		Long id = this.accountRepository.findByEmail("au17-old-refresh@example.com").orElseThrow().getId();
		Long bystander = this.accountRepository.findByEmail("au17-bystander-session@example.com").orElseThrow().getId();
		String token = 토큰을_심는다(id, TokenPurpose.PASSWORD_RESET);

		this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD)))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(post("/api/v1/auth/reissue")
						.contentType(MediaType.APPLICATION_JSON)
						.characterEncoding(StandardCharsets.UTF_8)
						.content("{\"refreshToken\": \"" + 세션.refreshToken() + "\"}"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A002"));

		assertThat(this.refreshTokenRepository.findByAccountId(id)).as("거부된 재발급이 행을 다시 만들지 않는다").isEmpty();
		assertThat(this.refreshTokenRepository.findByAccountId(bystander))
				.map(RefreshToken::getToken).as("다른 계정의 세션").contains(남의_세션.refreshToken());
	}

	/**
	 * 이미 발급된 Access Token 은 만료까지 남는다 — 비밀번호 변경과 같은 창이고 막는 코드를 두지 않는다
	 * (sp-docs/requirements/member.md §11.4, sp-docs/security.md §5.3). 즉시 차단을 넣으면 여기서 깨진다.
	 */
	@Test
	@DisplayName("확인 뒤에도 옛 Access Token 으로 보호 경로를 통과한다")
	void 재설정_확인_뒤_옛_Access_Token() throws Exception {
		IssuedTokens 세션 = 재설정할_계정과_세션을_만든다("au17-old-access@example.com");
		Long id = this.accountRepository.findByEmail("au17-old-access@example.com").orElseThrow().getId();
		String token = 토큰을_심는다(id, TokenPurpose.PASSWORD_RESET);

		this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD)))
				.andExpect(status().isNoContent());

		this.mockMvc.perform(getMe(세션.accessToken()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.email").value("au17-old-access@example.com"));
	}

	/**
	 * 키는 계정에 저장된 이메일을 AU-12 의 키 변환(ASCII 대문자만 소문자로, {@code LoginAttempt#emailKeyOf})으로 바꾼 값이다
	 * (sp-docs/requirements/member.md §11.4·§12.1). 그래서 저장된 이메일에 대문자를 섞고 행은 소문자 키로 심는다 — H2 는
	 * 데이터를 대소문자를 가려 비교하므로 변환 없이 만든 키는 이 행을 찾지 못한다(AU-17 실측). 인증된 계정과 미인증 계정이
	 * 둘 다 잠긴 행을 갖는다.
	 */
	@Test
	@DisplayName("확인 — 그 계정 이메일의 잠긴 행이 failed_count 0, locked_until NULL 이 된다. 다른 키의 행은 그대로다")
	void 재설정_확인이_잠금을_푼다() throws Exception {
		CLOCK.set(NOW);
		Long unverified = 미인증_계정을_만든다("AU17-Locked@Example.com");
		Long verified = 미인증_계정을_만든다("AU17-Locked-Verified@Example.com");
		인증을_채운다("AU17-Locked-Verified@Example.com", NOW.minusDays(1));
		잠긴_행을_심는다("au17-locked@example.com", 5, NOW.plusMinutes(15));
		잠긴_행을_심는다("au17-locked-verified@example.com", 5, NOW.plusMinutes(15));
		잠긴_행을_심는다("au17-locked-bystander@example.com", 5, NOW.plusMinutes(15));
		String unverifiedToken = 토큰을_심는다(unverified, TokenPurpose.PASSWORD_RESET);
		String verifiedToken = 토큰을_심는다(verified, TokenPurpose.PASSWORD_RESET);
		CLOCK.set(NOW.plusMinutes(1));

		this.mockMvc.perform(resetConfirm(재설정_확인_본문(unverifiedToken, NEW_PASSWORD)))
				.andExpect(status().isNoContent());
		this.mockMvc.perform(resetConfirm(재설정_확인_본문(verifiedToken, NEW_PASSWORD)))
				.andExpect(status().isNoContent());

		assertThat(잠금_행("au17-locked@example.com")).as("미인증 계정의 키").isEqualTo(new LockState(0, null));
		assertThat(잠금_행("au17-locked-verified@example.com")).as("인증된 계정의 키").isEqualTo(new LockState(0, null));
		assertThat(잠금_행("au17-locked-bystander@example.com")).as("다른 키")
				.isEqualTo(new LockState(5, NOW.plusMinutes(15)));
	}

	/**
	 * 재설정 링크를 연 것이 그 주소를 가졌다는 증명이다 — 미인증 계정은 확인이 인증도 채워 새 비밀번호로 로그인할 수 있다
	 * (sp-docs/requirements/member.md §11.4 의 6). 이미 인증된 계정은 처음 인증한 시각이 남는다. 두 계정 모두 잠금 행이 없다.
	 */
	@Test
	@DisplayName("확인 — 미인증 계정은 email_verified_at 이 확인 시각으로 채워져 새 비밀번호로 로그인한다. 이미 인증된 계정은 그대로다")
	void 재설정_확인이_미인증을_인증한다() throws Exception {
		CLOCK.set(NOW);
		Long unverified = 미인증_계정을_만든다("au17-unverified@example.com");
		Long verified = 미인증_계정을_만든다("au17-verified@example.com");
		인증을_채운다("au17-verified@example.com", NOW.minusDays(1));
		String unverifiedToken = 토큰을_심는다(unverified, TokenPurpose.PASSWORD_RESET);
		String verifiedToken = 토큰을_심는다(verified, TokenPurpose.PASSWORD_RESET);
		CLOCK.set(NOW.plusMinutes(1));

		this.mockMvc.perform(resetConfirm(재설정_확인_본문(unverifiedToken, NEW_PASSWORD)))
				.andExpect(status().isNoContent());
		this.mockMvc.perform(resetConfirm(재설정_확인_본문(verifiedToken, NEW_PASSWORD)))
				.andExpect(status().isNoContent());

		assertThat(인증_시각(unverified)).isEqualTo(NOW.plusMinutes(1));
		assertThat(인증_시각(verified)).isEqualTo(NOW.minusDays(1));
		this.mockMvc.perform(loginRequest("au17-unverified@example.com", NEW_PASSWORD))
				.andExpect(status().isOk());
	}

	/**
	 * {@code newPassword} 는 토큰을 쓰기 전에 거른다 — 규칙을 어긴 입력이 링크를 소모하지 않는다
	 * (sp-docs/requirements/member.md §11.4). 그래서 같은 토큰으로 다시 보내면 204 다. 빈 값은 존재와 규칙 두 제약에 함께
	 * 걸린다 — 둘 다 {@code newPassword} 이고 같은 메시지다.
	 */
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"{\"token\": \"%s\"}",
			"{\"token\": \"%s\", \"newPassword\": null}",
			"{\"token\": \"%s\", \"newPassword\": \"\"}",
			"{\"token\": \"%s\", \"newPassword\": \"Pw1!abc\"}",                // 7자
			"{\"token\": \"%s\", \"newPassword\": \"Passw0rd!Passw0rd!Pass\"}", // 22자
			"{\"token\": \"%s\", \"newPassword\": \"Password1\"}",              // 특수문자 없음
			"{\"token\": \"%s\", \"newPassword\": \"비밀번호1234\"}",             // 한글은 특수문자가 아니다 (§2.1)
			"{\"token\": \"%s\", \"newPassword\": \"Passw0rd 1\"}"              // 공백 금지 (§2.1)
	})
	@DisplayName("확인 — newPassword 가 비밀번호 규칙을 어기면 400 C001 이고 fieldErrors 에 newPassword 다. 토큰은 쓰이지 않아 같은 토큰으로 다시 확인하면 204 다")
	void 재설정_확인_newPassword_위반(String template) throws Exception {
		Long id = 미인증_계정을_만든다("au17-new-password@example.com");
		String token = 토큰을_심는다(id, TokenPurpose.PASSWORD_RESET);
		String password = 컬럼(id, "password");

		this.mockMvc.perform(resetConfirm(template.formatted(token)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors").isNotEmpty())
				.andExpect(jsonPath("$.error.fieldErrors[*].field", everyItem(equalTo("newPassword"))))
				.andExpect(jsonPath("$.error.fieldErrors[*].message", everyItem(equalTo(PASSWORD_MESSAGE))));

		assertThat(사용_시각(token)).as("토큰을 쓰기 전에 걸렀다").isNull();
		assertThat(컬럼(id, "password")).isEqualTo(password);

		this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD)))
				.andExpect(status().isNoContent());
	}

	/** 맞지 않는 토큰이어도 {@code newPassword} 의 위반이 먼저 답한다 — 그 검증이 토큰을 쓰기 전에 돈다. */
	@Test
	@DisplayName("확인 — 맞지 않는 토큰과 규칙을 어긴 newPassword 가 함께 오면 400 C001 이고 fieldErrors 는 newPassword 하나다")
	void 재설정_확인_둘_다_틀리면_C001() throws Exception {
		this.mockMvc.perform(resetConfirm(재설정_확인_본문("not-a-token", "short")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors.length()").value(1))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("newPassword"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(PASSWORD_MESSAGE));
	}

	/**
	 * 수명은 발급 작업이 정한 30분이다 (sp-docs/requirements/member.md §11.1). 사용 처리가 {@code expires_at > now} 를 보므로
	 * 발급 뒤 30분에서 1초 모자라면 받고, 꼭 30분이면 받지 않는다. 토큰은 재설정 요청의 실제 발급으로 만든다 — 만료 시각을
	 * 이 테스트가 심지 않는다.
	 */
	@Test
	@DisplayName("확인 — 수명 경계: 발급 뒤 30분에서 1초 모자라면 204, 꼭 30분이면 400 AU007 이고 비밀번호가 그대로다")
	void 재설정_확인_수명_경계() throws Exception {
		CLOCK.set(NOW);
		미인증_계정을_만든다("au17-expiry-inside@example.com");
		Long boundary = 미인증_계정을_만든다("au17-expiry-boundary@example.com");
		String insideToken = 재설정을_요청하고_토큰을_꺼낸다("au17-expiry-inside@example.com");
		String boundaryToken = 재설정을_요청하고_토큰을_꺼낸다("au17-expiry-boundary@example.com");
		String boundaryPassword = 컬럼(boundary, "password");

		CLOCK.set(NOW.plusMinutes(30).minusSeconds(1));
		this.mockMvc.perform(resetConfirm(재설정_확인_본문(insideToken, NEW_PASSWORD)))
				.andExpect(status().isNoContent());

		CLOCK.set(NOW.plusMinutes(30));
		링크_토큰_오류다(this.mockMvc.perform(resetConfirm(재설정_확인_본문(boundaryToken, NEW_PASSWORD))));

		assertThat(사용_시각(insideToken)).isEqualTo(NOW.plusMinutes(30).minusSeconds(1));
		assertThat(사용_시각(boundaryToken)).isNull();
		assertThat(컬럼(boundary, "password")).isEqualTo(boundaryPassword);
	}

	@Test
	@DisplayName("확인 — 같은 토큰을 두 번 보내면 둘째가 400 AU007 이고 첫째가 정한 비밀번호가 그대로다")
	void 재설정_확인_같은_토큰_두_번() throws Exception {
		Long id = 미인증_계정을_만든다("au17-twice@example.com");
		String token = 토큰을_심는다(id, TokenPurpose.PASSWORD_RESET);

		this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD)))
				.andExpect(status().isNoContent());
		String password = 컬럼(id, "password");

		링크_토큰_오류다(this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, "Third1!pw"))));

		assertThat(컬럼(id, "password")).isEqualTo(password);
	}

	@Test
	@DisplayName("확인 — 인증 목적의 토큰은 400 AU007 이다. 그 토큰은 쓰이지 않고 비밀번호·인증이 그대로다")
	void 재설정_확인_인증_목적의_토큰() throws Exception {
		Long id = 미인증_계정을_만든다("au17-verification-purpose@example.com");
		String token = 토큰을_심는다(id, TokenPurpose.EMAIL_VERIFICATION);
		String password = 컬럼(id, "password");

		링크_토큰_오류다(this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD))));

		assertThat(사용_시각(token)).isNull();
		assertThat(컬럼(id, "password")).isEqualTo(password);
		assertThat(인증_시각(id)).isNull();
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"{\"newPassword\": \"" + NEW_PASSWORD + "\"}",
			"{\"token\": null, \"newPassword\": \"" + NEW_PASSWORD + "\"}",
			"{\"token\": \"\", \"newPassword\": \"" + NEW_PASSWORD + "\"}",
			"{\"token\": \"   \", \"newPassword\": \"" + NEW_PASSWORD + "\"}"
	})
	@DisplayName("확인 — token 누락·null·빈 값은 400 C001 이고 fieldErrors 에 token 이다")
	void 재설정_확인_token_누락(String json) throws Exception {
		this.mockMvc.perform(resetConfirm(json))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors.length()").value(1))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("token"))
				.andExpect(jsonPath("$.error.fieldErrors[0].message").value(TOKEN_MESSAGE));
	}

	/**
	 * 형식 검증을 걸지 않는다 (sp-docs/api-contract.md §2.4) — 길이·문자 집합이 틀린 토큰은 맞지 않는 토큰이고 400
	 * {@code C001} 이 아니라 {@code AU007} 이다. 발급하는 토큰은 43자의 base64url 이다(AU-15).
	 */
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"a",
			// 42자·44자 — 발급하는 길이의 바로 안팎
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			// 43자지만 base64url 밖의 문자
			"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
			"토큰",
			"has space"
	})
	@DisplayName("확인 — 길이·문자가 틀린 token 은 C001 이 아니라 400 AU007 이다")
	void 재설정_확인_형식이_틀린_token(String token) throws Exception {
		링크_토큰_오류다(this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD))));
	}

	@Test
	@DisplayName("확인 — 아주 긴 token 도 400 AU007 이다")
	void 재설정_확인_아주_긴_token() throws Exception {
		링크_토큰_오류다(this.mockMvc.perform(resetConfirm(재설정_확인_본문("A".repeat(10_000), NEW_PASSWORD))));
	}

	@Test
	@DisplayName("확인 — 탈퇴한 계정은 400 AU007 이다. 비밀번호·email_verified_at 이 그대로이고 토큰의 사용 처리도 되돌려진다")
	void 재설정_확인_탈퇴한_계정() throws Exception {
		Long id = 미인증_계정을_만든다("au17-withdrawn@example.com");
		String token = 토큰을_심는다(id, TokenPurpose.PASSWORD_RESET);
		탈퇴시킨다("au17-withdrawn@example.com");
		String password = 컬럼(id, "password");

		링크_토큰_오류다(this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD))));

		assertThat(컬럼(id, "password")).as("닫힌 행에 쓰지 않는다").isEqualTo(password);
		assertThat(인증_시각(id)).isNull();
		assertThat(사용_시각(token)).as("사용 처리가 확인의 트랜잭션과 함께 되돌려진다").isNull();
	}

	/** 탈퇴 검사가 인증 여부보다 먼저다 — 인증된 계정이어도 탈퇴했으면 204 가 아니다 (sp-docs/requirements/member.md §11.4 의 2). */
	@Test
	@DisplayName("확인 — 이미 인증된 계정도 탈퇴했으면 400 AU007 이다. 비밀번호·email_verified_at 이 그대로이고 토큰의 사용 처리도 되돌려진다")
	void 재설정_확인_인증된_뒤_탈퇴한_계정() throws Exception {
		CLOCK.set(NOW);
		Long id = 미인증_계정을_만든다("au17-verified-withdrawn@example.com");
		인증을_채운다("au17-verified-withdrawn@example.com", NOW.minusDays(1));
		String token = 토큰을_심는다(id, TokenPurpose.PASSWORD_RESET);
		탈퇴시킨다("au17-verified-withdrawn@example.com");
		String password = 컬럼(id, "password");

		링크_토큰_오류다(this.mockMvc.perform(resetConfirm(재설정_확인_본문(token, NEW_PASSWORD))));

		assertThat(컬럼(id, "password")).as("닫힌 행에 쓰지 않는다").isEqualTo(password);
		assertThat(인증_시각(id)).as("처음 인증한 시각이 그대로다").isEqualTo(NOW.minusDays(1));
		assertThat(사용_시각(token)).as("사용 처리가 확인의 트랜잭션과 함께 되돌려진다").isNull();
	}

	// --- AU-17 도우미 ---

	private static MockHttpServletRequestBuilder resetRequest(String json) {
		return post("/api/v1/accounts/password-reset")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

	private static MockHttpServletRequestBuilder resetConfirm(String json) {
		return post("/api/v1/accounts/password-reset/confirm")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content(json);
	}

	private static String 재설정_확인_본문(String token, String newPassword) {
		return "{\"token\": \"" + token + "\", \"newPassword\": \"" + newPassword + "\"}";
	}

	/** 재설정 메일의 링크가 설정의 기준 주소로 시작하는지 보고 토큰을 꺼낸다. */
	private static String 재설정_링크의_토큰(InMemoryMailer.Sent sent) {
		Matcher matcher = RESET_LINK.matcher(sent.mail().text());
		assertThat(matcher.find()).as("본문의 링크가 설정의 기준 주소로 시작한다: " + RESET_LINK.pattern()).isTrue();
		return matcher.group(1);
	}

	/**
	 * 재설정을 요청하고 그 메일의 토큰을 꺼낸다. 계정은 활성이어야 한다. 앞서 발송 실행기에 넘어간 일이 끝나기를 기다린 뒤 남은
	 * 메일을 버린다 — 가입이 넘긴 인증 메일이 섞이지 않는다.
	 */
	private String 재설정을_요청하고_토큰을_꺼낸다(String email) throws Exception {
		MailExecutorDrain.drain(this.mailExecutor);
		this.inMemoryMailer.clear();
		this.mockMvc.perform(resetRequest("{\"email\": \"" + email + "\"}"))
				.andExpect(status().isAccepted());
		InMemoryMailer.Sent sent = this.inMemoryMailer.next(Duration.ofSeconds(5));
		assertThat(sent.mail().to()).isEqualTo(email);
		assertThat(sent.mail().purpose()).isEqualTo(TokenPurpose.PASSWORD_RESET.name());
		return 재설정_링크의_토큰(sent);
	}

	/**
	 * {@link #계정과_세션을_만든다(String)} 뒤에 가입이 발송 실행기에 넘긴 일이 끝나기를 기다린다 — 그 인증 메일의 발급이
	 * 테스트의 확인과 겹치지 않는다.
	 */
	private IssuedTokens 재설정할_계정과_세션을_만든다(String email) throws Exception {
		IssuedTokens tokens = 계정과_세션을_만든다(email);
		MailExecutorDrain.drain(this.mailExecutor);
		this.inMemoryMailer.clear();
		return tokens;
	}

	/**
	 * 잠긴 {@code login_attempt} 행을 SQL 로 심는다. 잠그는 쪽(실패 세기, sp-docs/domain-model.md §2.5)은 이 항목의 범위가
	 * 아니다 — 그 경로를 거치지 않고 행의 값을 이 테스트가 정한다.
	 */
	private void 잠긴_행을_심는다(String emailKey, int failedCount, LocalDateTime lockedUntil) {
		this.jdbcTemplate.update(
				"insert into login_attempt (email_key, failed_count, locked_until, updated_at) values (?, ?, ?, ?)",
				emailKey, failedCount, lockedUntil, NOW);
	}

	/** 커밋된 {@code login_attempt} 행의 잠금 값. JPA 를 거치지 않는다. */
	private LockState 잠금_행(String emailKey) {
		return this.jdbcTemplate.queryForObject(
				"select failed_count, locked_until from login_attempt where email_key = ?",
				(rs, rowNum) -> new LockState(rs.getInt("failed_count"), rs.getObject("locked_until", LocalDateTime.class)),
				emailKey);
	}

	/** {@code login_attempt} 의 연속 실패 수와 잠금 시각. */
	private record LockState(int failedCount, LocalDateTime lockedUntil) { }

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
