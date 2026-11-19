package com.example.auth.account.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.MutableClock;
import com.example.auth.support.TestRsaKeys;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * AU-20 — 계정 목록 (ADMIN). 정본: sp-docs/api-contract.md §2.5·§7.1·§9.12, sp-docs/plan/phase2-auth-member.md AU-20 의
 * 검증 표.
 *
 * <p>H2 는 테스트 클래스 사이에 공유되고 seed ADMIN(id 1)이 남아 있다. 그래서 목록의 내용을 보는 테스트는 이 클래스가 만든
 * 계정만 걸리는 {@code email} 조건({@value #DOMAIN})을 쓰거나, 시각을 먼 미래로 박아 첫 페이지의 앞에 오게 한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountListControllerTest {

	private static final String PATH = "/api/v1/accounts";

	private static final String ADMIN_EMAIL = "admin@example.com";

	/** 이 클래스가 만든 계정의 이메일 끝. */
	private static final String DOMAIN = "@list.test";

	private static final LocalDateTime NOW = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	private static final MutableClock CLOCK = new MutableClock();

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	/** 애플리케이션의 {@code Clock} 빈을 {@link #CLOCK} 로 바꾼다. {@code locked} 의 판정 시각이 이것이다. */
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
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	/** seed 행은 남긴다 — 다른 테스트 클래스가 그것을 쓴다. {@code login_attempt} 는 계정을 참조하지 않는다. */
	@AfterEach
	void 정리() {
		CLOCK.reset();
		this.jdbcTemplate.update("delete from login_attempt");
		this.accountRepository.deleteAll(this.accountRepository.findAll().stream()
				.filter(account -> !ADMIN_EMAIL.equals(account.getEmail()))
				.toList());
	}

	@Test
	@DisplayName("파라미터가 없으면 200, 기본 size 20·page 0, latest(created_at DESC, 같으면 id DESC)이고 §7.1 의 모양이다")
	void 기본값() throws Exception {
		Long a = 계정("a" + DOMAIN, Role.USER);
		Long b = 계정("b" + DOMAIN, Role.USER);
		Long c = 계정("c" + DOMAIN, Role.USER);
		// b·c 는 같은 시각, a 는 그보다 이르다. 먼 미래라 seed 와 다른 클래스의 행보다 앞에 온다
		생성시각(a, LocalDateTime.of(2099, 1, 1, 0, 0, 0));
		생성시각(b, LocalDateTime.of(2099, 1, 1, 0, 0, 1));
		생성시각(c, LocalDateTime.of(2099, 1, 1, 0, 0, 1));

		ResultActions result = this.mockMvc.perform(목록(관리자_토큰()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.error").isEmpty())
				.andExpect(jsonPath("$.data.page").value(0))
				.andExpect(jsonPath("$.data.size").value(20))
				.andExpect(jsonPath("$.data.first").value(true))
				.andExpect(jsonPath("$.data.last").isBoolean())
				.andExpect(jsonPath("$.data.totalElements").isNumber())
				.andExpect(jsonPath("$.data.totalPages").isNumber());

		List<Number> ids = JsonPath.read(본문(result), "$.data.content[0:3].id");
		assertThat(ids).extracting(Number::longValue).containsExactly(c, b, a);
		Map<String, Object> data = JsonPath.read(본문(result), "$.data");
		assertThat(data.keySet())
				.containsExactly("content", "page", "size", "totalElements", "totalPages", "first", "last");
	}

	@Test
	@DisplayName("원소의 키가 §2.5 의 표와 같다 — password·인증 시각·잠금 시각·닉네임이 없다")
	void 원소의_키() throws Exception {
		Long id = 계정("keys" + DOMAIN, Role.USER);
		생성시각(id, LocalDateTime.of(2026, 10, 1, 8, 59, 0));

		ResultActions result = this.mockMvc.perform(목록(관리자_토큰()).param("email", "keys" + DOMAIN))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.content", hasSize(1)))
				.andExpect(jsonPath("$.data.content[0].id").value(id))
				.andExpect(jsonPath("$.data.content[0].email").value("keys" + DOMAIN))
				.andExpect(jsonPath("$.data.content[0].role").value("USER"))
				.andExpect(jsonPath("$.data.content[0].deleted").value(false))
				.andExpect(jsonPath("$.data.content[0].createdAt").value("2026-10-01T08:59:00"))
				.andExpect(jsonPath("$.data.content[0].emailVerified").value(true))
				.andExpect(jsonPath("$.data.content[0].locked").value(false));

		Map<String, Object> element = JsonPath.read(본문(result), "$.data.content[0]");
		assertThat(element.keySet())
				.containsExactly("id", "email", "role", "deleted", "createdAt", "emailVerified", "locked");
		assertThat(본문(result)).doesNotContain("password").doesNotContain("nickname");
	}

	@Test
	@DisplayName("sort=email 은 email ASC, id ASC 다")
	void 이메일_정렬() throws Exception {
		Long b = 계정("sb" + DOMAIN, Role.USER);
		Long a = 계정("sa" + DOMAIN, Role.USER);
		Long c = 계정("sc" + DOMAIN, Role.USER);

		ResultActions result = this.mockMvc.perform(목록(관리자_토큰()).param("sort", "email").param("email", DOMAIN))
				.andExpect(status().isOk());

		List<Number> ids = JsonPath.read(본문(result), "$.data.content[*].id");
		assertThat(ids).extracting(Number::longValue).containsExactly(a, b, c);
	}

	@Test
	@DisplayName("email 은 그 문자열을 포함하는 계정만이다(부분 일치 — 앞·가운데)")
	void 이메일_부분_일치() throws Exception {
		// 다른 테스트가 공유 DB 에 남긴 *@example.com 행이 걸리지 않는 값으로 거른다 — 걸리면 첫 페이지가 밀린다
		Long hit1 = 계정("zqexam1" + DOMAIN, Role.USER);
		Long hit2 = 계정("my-zqexam" + DOMAIN, Role.USER);
		계정("other" + DOMAIN, Role.USER);

		ResultActions result = this.mockMvc.perform(목록(관리자_토큰()).param("email", "zqexam").param("sort", "email"))
				.andExpect(status().isOk());

		List<String> emails = JsonPath.read(본문(result), "$.data.content[*].email");
		assertThat(emails).allSatisfy(email -> assertThat(email).contains("zqexam"));
		List<Number> ids = JsonPath.read(본문(result), "$.data.content[*].id");
		assertThat(ids).extracting(Number::longValue).contains(hit1, hit2);
		assertThat(emails).doesNotContain("other" + DOMAIN);
	}

	@Test
	@DisplayName("공백만인 email 은 조건이 없는 것과 같다")
	void 공백_이메일() throws Exception {
		계정("blank1" + DOMAIN, Role.USER);
		계정("blank2" + DOMAIN, Role.USER);

		long all = 전체_수(목록(관리자_토큰()));
		long blank = 전체_수(목록(관리자_토큰()).param("email", "   "));

		assertThat(blank).isEqualTo(all).isGreaterThanOrEqualTo(3);
	}

	@Test
	@DisplayName("role=ADMIN·deleted=true 는 그 조건의 계정만이다")
	void 역할과_탈퇴_조건() throws Exception {
		Long admin = 계정("admin2" + DOMAIN, Role.ADMIN);
		Long deletedUser = 계정("gone" + DOMAIN, Role.USER);
		Long deletedAdmin = 계정("gone-admin" + DOMAIN, Role.ADMIN);
		계정("alive" + DOMAIN, Role.USER);
		탈퇴(deletedUser);
		탈퇴(deletedAdmin);

		List<Number> admins = JsonPath.read(본문(this.mockMvc.perform(
				목록(관리자_토큰()).param("role", "ADMIN").param("email", DOMAIN))), "$.data.content[*].id");
		assertThat(admins).extracting(Number::longValue).containsExactlyInAnyOrder(admin, deletedAdmin);

		List<Number> deleted = JsonPath.read(본문(this.mockMvc.perform(
				목록(관리자_토큰()).param("deleted", "true").param("email", DOMAIN))), "$.data.content[*].id");
		assertThat(deleted).extracting(Number::longValue).containsExactlyInAnyOrder(deletedUser, deletedAdmin);

		List<Number> both = JsonPath.read(본문(this.mockMvc.perform(목록(관리자_토큰())
				.param("role", "ADMIN").param("deleted", "true").param("email", DOMAIN))), "$.data.content[*].id");
		assertThat(both).extracting(Number::longValue).containsExactly(deletedAdmin);

		ResultActions alive = this.mockMvc.perform(목록(관리자_토큰()).param("deleted", "false").param("email", DOMAIN));
		List<Boolean> flags = JsonPath.read(본문(alive), "$.data.content[*].deleted");
		assertThat(flags).hasSize(2).containsOnly(false);
	}

	@Test
	@DisplayName("최대보다 큰 size 는 최대값(50)으로 절삭한다 — 응답의 size 가 50 이다")
	void 사이즈_절삭() throws Exception {
		this.mockMvc.perform(목록(관리자_토큰()).param("size", "51"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.size").value(50));
		this.mockMvc.perform(목록(관리자_토큰()).param("size", "50"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.size").value(50));
	}

	@ParameterizedTest(name = "{0}={1}")
	@CsvSource({"page, -1", "size, 0"})
	@DisplayName("page 음수·size 1 미만은 400 C001, fieldErrors 1건")
	void 하한_위반(String name, String value) throws Exception {
		this.mockMvc.perform(목록(관리자_토큰()).param(name, value))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors", hasSize(1)))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value(name));
	}

	@Test
	@DisplayName("email 101자는 400 C001, fieldErrors 1건. 100자는 통과한다")
	void 이메일_길이() throws Exception {
		this.mockMvc.perform(목록(관리자_토큰()).param("email", "a".repeat(101)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.fieldErrors", hasSize(1)))
				.andExpect(jsonPath("$.error.fieldErrors[0].field").value("email"));
		this.mockMvc.perform(목록(관리자_토큰()).param("email", "a".repeat(100)))
				.andExpect(status().isOk());
	}

	@ParameterizedTest(name = "{0}={1}")
	@CsvSource({"sort, bogus", "role, bogus", "deleted, maybe", "sort, LATEST", "role, admin"})
	@DisplayName("sort·role·deleted 의 틀린 값은 400 C002 다")
	void 바인딩_실패(String name, String value) throws Exception {
		this.mockMvc.perform(목록(관리자_토큰()).param(name, value))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C002"));
	}

	@Test
	@DisplayName("USER 토큰은 403 A004 다")
	void 사용자_토큰() throws Exception {
		Long user = 계정("user" + DOMAIN, Role.USER);

		this.mockMvc.perform(목록(this.jwtTokenProvider.issue(user, Role.USER).accessToken()))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").isEmpty())
				.andExpect(jsonPath("$.error.code").value("A004"));
	}

	@Test
	@DisplayName("토큰이 없으면 401 A001 이다")
	void 토큰_없음() throws Exception {
		this.mockMvc.perform(get(PATH))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error.code").value("A001"));
	}

	/**
	 * 키는 AU-12 의 변환(ASCII 대문자만 소문자)이다 — 계정 이메일에 대문자를 두고 행은 변환한 키로 심는다. 판정 시각은 주입한
	 * 시계다 — {@code locked_until} 이 그보다 뒤일 때만 잠겼다. 같은 시각이면 풀렸다.
	 */
	@Test
	@DisplayName("잠긴 이메일의 계정은 locked: true, 시계를 잠금 시각(그리고 그 너머)으로 옮기면 false 다")
	void 잠금() throws Exception {
		계정("Locked" + DOMAIN, Role.USER);
		계정("free" + DOMAIN, Role.USER);
		LocalDateTime lockedUntil = NOW.plusMinutes(15);
		this.jdbcTemplate.update(
				"insert into login_attempt (email_key, failed_count, locked_until, updated_at) values (?, 0, ?, ?)",
				"locked" + DOMAIN, Timestamp.valueOf(lockedUntil), Timestamp.valueOf(NOW));

		CLOCK.set(NOW);
		this.mockMvc.perform(목록(관리자_토큰()).param("email", "Locked" + DOMAIN))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.content", hasSize(1)))
				.andExpect(jsonPath("$.data.content[0].locked").value(true));
		this.mockMvc.perform(목록(관리자_토큰()).param("email", "free" + DOMAIN))
				.andExpect(jsonPath("$.data.content", hasSize(1)))
				.andExpect(jsonPath("$.data.content[0].locked").value(false));

		CLOCK.set(lockedUntil.minusSeconds(1));
		this.mockMvc.perform(목록(관리자_토큰()).param("email", "Locked" + DOMAIN))
				.andExpect(jsonPath("$.data.content[0].locked").value(true));

		CLOCK.set(lockedUntil);
		this.mockMvc.perform(목록(관리자_토큰()).param("email", "Locked" + DOMAIN))
				.andExpect(jsonPath("$.data.content[0].locked").value(false));

		CLOCK.set(lockedUntil.plusMinutes(1));
		this.mockMvc.perform(목록(관리자_토큰()).param("email", "Locked" + DOMAIN))
				.andExpect(jsonPath("$.data.content[0].locked").value(false));
	}

	@Test
	@DisplayName("미인증 계정은 emailVerified: false 다")
	void 미인증() throws Exception {
		this.accountRepository.saveAndFlush(Account.builder()
				.email("unverified" + DOMAIN)
				.password(this.passwordEncoder.encode("Passw0rd!"))
				.role(Role.USER)
				.build());

		this.mockMvc.perform(목록(관리자_토큰()).param("email", "unverified" + DOMAIN))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.content", hasSize(1)))
				.andExpect(jsonPath("$.data.content[0].emailVerified").value(false));
	}

	/** 인증된 계정을 만든다. 비밀번호 해시는 실행 중에 만든다. */
	private Long 계정(String email, Role role) {
		Account account = Account.builder()
				.email(email)
				.password(this.passwordEncoder.encode("Passw0rd!"))
				.role(role)
				.build();
		account.markEmailVerified(Clock.systemDefaultZone());
		return this.accountRepository.saveAndFlush(account).getId();
	}

	private void 생성시각(Long id, LocalDateTime createdAt) {
		this.jdbcTemplate.update("update account set created_at = ? where id = ?", Timestamp.valueOf(createdAt), id);
	}

	private void 탈퇴(Long id) {
		this.jdbcTemplate.update("update account set deleted = true where id = ?", id);
	}

	/** seed ADMIN(id 1)의 토큰. 발급은 계정 행을 보지 않는다. */
	private String 관리자_토큰() {
		return this.jwtTokenProvider.issue(1L, Role.ADMIN).accessToken();
	}

	private static MockHttpServletRequestBuilder 목록(String accessToken) {
		return get(PATH).header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
	}

	private long 전체_수(MockHttpServletRequestBuilder request) throws Exception {
		Number total = JsonPath.read(본문(this.mockMvc.perform(request).andExpect(status().isOk())),
				"$.data.totalElements");
		return total.longValue();
	}

	private static String 본문(ResultActions result) {
		try {
			return result.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
		} catch (java.io.UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}

}
