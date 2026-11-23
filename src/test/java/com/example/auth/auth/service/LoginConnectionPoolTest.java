package com.example.auth.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.example.auth.account.entity.Account;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.support.TestRsaKeys;
import com.jayway.jsonpath.JsonPath;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * 로그인 하나가 연결을 둘 쥐지 않는지 작은 풀에서 본다 — 2026-11-16 AU-18 리뷰가 잰 결함의 회귀 테스트다. 로그인 전체가 한
 * 트랜잭션이면 BCrypt 비교 동안 그 트랜잭션이 연결을 쥐고, 비교 뒤의 잠금 판정·세기가 카운터 빈의 새 트랜잭션으로 연결을 하나
 * 더 얻는다. 그 리뷰가 풀 2 에서 BCrypt 뒤에 맞춘 동시 로그인 둘을 보냈더니 둘이 서로 쥔 연결을 기다리다 둘 다 연결을 얻지
 * 못했다(500 {@code C005}, 실패는 하나도 세지 못했다). 검증을 트랜잭션 밖에서 하는 이유는 {@link AuthService#login} 에 있다.
 *
 * <p>풀 크기는 컨텍스트의 설정이라 풀을 2 로 줄인 컨텍스트를 따로 띄우고, 끝나면 닫아 캐시에 남기지 않는다. 연결 대기는 3초로
 * 줄인다 — 결함이 되돌아오면 기본 대기만큼 기다리지 않고 실패한다.
 *
 * <p>두 요청은 실제 스레드에서 HTTP 로 보낸다. 둘 다 BCrypt 비교를 마친 자리에서 서로를 기다렸다가 함께 잠금 판정·세기로
 * 들어간다. 둘이 모인 순간에 풀이 빌려 준 연결 수를 잰다. 세는 행은 미리 심는다 — 두 세기가 모두 있는 행을 갱신하는 같은 모양이
 * 되어, 새 키를 넣는 쪽과 갱신하는 쪽이 섞이지 않는다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
		"spring.datasource.hikari.maximum-pool-size=2",
		"spring.datasource.hikari.connection-timeout=3000"
})
@DirtiesContext
class LoginConnectionPoolTest {

	private static final String RAW_PASSWORD = "Passw0rd!";

	private static final String WRONG_PASSWORD = "Other1!pw";

	/** V3 seed 의 계정 (sp-docs/requirements/member.md §10.1). 정리가 남긴다. */
	private static final String ADMIN_EMAIL = "admin@example.com";

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	/** BCrypt 비교가 끝나는 자리에서 두 요청을 맞춘다. 나머지는 실제 빈에 위임된다 — 픽스처의 인코딩도 실제 빈이 한다. */
	@MockitoSpyBean
	private PasswordEncoder spyPasswordEncoder;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private AccountRepository accountRepository;

	/** 커밋된 값을 읽고 심는다. 테스트 스레드에는 트랜잭션이 없다. */
	@Autowired
	private JdbcTemplate jdbcTemplate;

	/** 풀이 빌려 준 연결 수를 읽는다. */
	@Autowired
	private DataSource dataSource;

	/** 두 요청을 보내는 스레드들. */
	private ExecutorService requests;

	/** 만든 행을 지운다. H2 는 테스트 클래스 사이에 공유되므로({@code DB_CLOSE_DELAY=-1}) 계정은 seed 를 남긴다. */
	@AfterEach
	void 정리() {
		if (this.requests != null) {
			this.requests.shutdownNow();
		}
		this.jdbcTemplate.update("delete from account_token");
		this.jdbcTemplate.update("delete from login_attempt");
		this.jdbcTemplate.update("delete from refresh_token");
		this.jdbcTemplate.update("delete from account where email <> ?", ADMIN_EMAIL);
	}

	@Test
	@DisplayName("풀 2 에서 BCrypt 비교 뒤에 맞춘 동시 로그인 둘이 모두 401 AU003 이고 둘 다 세진다 — 비교를 마친 요청이 쥔 연결이 없다")
	void BCrypt_뒤에_맞춘_동시_로그인이_연결을_기다리지_않는다() throws Exception {
		String email = "au18-pool-concurrent@example.com";
		String key = LoginAttempt.emailKeyOf(email);
		계정을_만든다(email);
		this.jdbcTemplate.update(
				"insert into login_attempt (email_key, failed_count, locked_until, updated_at) values (?, ?, ?, ?)",
				key, 0, null, LocalDateTime.now().minusMinutes(1));
		List<Integer> 모인_순간의_빌린_연결 = new CopyOnWriteArrayList<>();
		CyclicBarrier 비교_뒤 = new CyclicBarrier(2, () -> 모인_순간의_빌린_연결.add(빌려_준_연결()));
		willAnswer(invocation -> {
			Object matched = invocation.callRealMethod();
			비교_뒤.await(10, TimeUnit.SECONDS);
			return matched;
		}).given(this.spyPasswordEncoder).matches(any(), any());
		this.requests = Executors.newFixedThreadPool(2);

		List<Future<MockHttpServletResponse>> responses = new ArrayList<>();
		for (int i = 0; i < 2; i++) {
			responses.add(this.requests.submit(
					() -> this.mockMvc.perform(로그인(email, WRONG_PASSWORD)).andReturn().getResponse()));
		}

		for (Future<MockHttpServletResponse> future : responses) {
			MockHttpServletResponse response = future.get(30, TimeUnit.SECONDS);
			String body = response.getContentAsString(StandardCharsets.UTF_8);
			assertThat(response.getStatus()).as(body).isEqualTo(401);
			assertThat(JsonPath.<String>read(body, "$.error.code")).isEqualTo("AU003");
		}
		assertThat(모인_순간의_빌린_연결).as("BCrypt 비교를 마친 두 요청이 모인 순간에 풀이 빌려 준 연결").containsExactly(0);
		assertThat(this.jdbcTemplate.queryForObject(
				"select failed_count from login_attempt where email_key = ?", Integer.class, key))
				.as("두 실패가 모두 세졌다")
				.isEqualTo(2);
	}

	private int 빌려_준_연결() {
		try {
			return this.dataSource.unwrap(HikariDataSource.class).getHikariPoolMXBean().getActiveConnections();
		} catch (SQLException e) {
			throw new IllegalStateException(e);
		}
	}

	/** 인증된 계정. 비밀번호는 런타임에 인코딩한다 — 해시를 테스트 파일에 적지 않는다 (sp-docs/requirements/member.md §10.2). */
	private void 계정을_만든다(String email) {
		Account account = Account.builder().email(email).password(this.spyPasswordEncoder.encode(RAW_PASSWORD)).build();
		account.markEmailVerified(Clock.systemDefaultZone());
		this.accountRepository.saveAndFlush(account);
	}

	private static MockHttpServletRequestBuilder 로그인(String email, String password) {
		return post("/api/v1/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.characterEncoding(StandardCharsets.UTF_8)
				.content("{\"email\": \"" + email + "\", \"password\": \"" + password + "\"}");
	}

}
