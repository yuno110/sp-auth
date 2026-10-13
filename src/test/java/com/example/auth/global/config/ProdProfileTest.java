package com.example.auth.global.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.support.TestRsaKeys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * {@code application-prod.yml} 이 운영에서 꺼야 하는 것을 실제로 끄는지 본다
 * (sp-docs/plan/phase1.md §4 AU-11 의 "검증").
 *
 * <p><b>프로파일 순서는 지금 결과를 바꾸지 않는다.</b> {@code application-prod.yml} 과
 * {@code application-test.yml} 이 적는 키가 겹치지 않아 어느 순서로 선언해도 같은 설정으로
 * 해석된다 (실측). 그래서 DB 접속은 {@code application-test.yml} 의 H2 가 쓰이고
 * (sp-docs/tech-stack.md §5.3), {@code application-test.yml} 이 건드리지 않는 springdoc·로그
 * 설정은 {@code application-prod.yml} 의 값이 그대로 보인다.
 *
 * <p><b>{@code test} 를 나중에 적는 것은 안전장치다.</b> 뒤에 온 프로파일의 설정이 이기므로,
 * {@code application-prod.yml} 이 뒤에 환경값을 받는 datasource 설정을 갖게 되어 키가 겹치면
 * 그때 {@code test} 의 H2 가 이겨 이 테스트가 실제 DB 로 끌려가지 않는다.
 *
 * <p>운영 MySQL·실제 개인키에 의존하지 않으므로 다른 PC·CI 에서도 돈다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"prod", "test"})
class ProdProfileTest {

	/** 개인키는 저장소 밖에 있다. 테스트가 실행 시점에 만든 키 페어를 쓴다. */
	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private Environment environment;

	/**
	 * {@code /swagger-ui.html} 과 {@code /v3/api-docs} 를 함께 본다. UI 만 꺼도 후자가 열려
	 * 있으면 전체 엔드포인트 목록을 얻을 수 있다.
	 *
	 * <p>{@code SecurityConfig} 는 두 경로를 {@code permitAll} 로 두므로 — 경로별 인가는
	 * 프로파일을 모른다 — 404 를 만드는 것은 springdoc 쪽 설정이다.
	 */
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"/swagger-ui.html", "/swagger-ui/index.html", "/v3/api-docs"})
	@DisplayName("prod 프로파일에서 API 문서 경로가 404 다")
	void prod_에서_api_문서가_닫힌다(String path) throws Exception {
		this.mockMvc.perform(get(path))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.error.code").value("C004"));
	}

	/**
	 * SQL 로그는 로컬 프로파일만 ON 이다 (sp-docs/nfr.md §5). 바인드 파라미터 로그에는
	 * 비밀번호가 실리므로 운영에서 켜지면 그대로 평문이 남는다 (sp-docs/conventions.md §8).
	 *
	 * <p><b>효과가 아니라 설정값을 단언한다.</b> 루트 수준 기본이 {@code INFO} 라
	 * {@code logging.level} 블록이 없어도 두 로거는 이미 조용하다 — 로거의 활성 여부를 보는
	 * 단언은 블록이 사라진 것을 잡지 못한다. 블록이 일하는 순간은 루트 수준이 올라갈 때
	 * ({@code LOGGING_LEVEL_ROOT=DEBUG}) 이고, 비밀번호 평문이 샐 수 있는 순간이 그때다.
	 */
	@Test
	@DisplayName("prod 프로파일에서 SQL 로그와 바인드 파라미터 로그가 꺼진다")
	void prod_에서_sql_로그가_꺼진다() {
		assertThat(this.environment.getProperty("spring.jpa.show-sql", Boolean.class))
				.isFalse();
		assertThat(this.environment.getProperty("logging.level.org.hibernate.SQL"))
				.as("Hibernate 는 SQL 을 DEBUG 로 남긴다")
				.isEqualTo("warn");
		assertThat(this.environment.getProperty("logging.level.org.hibernate.orm.jdbc.bind"))
				.as("바인드 파라미터는 TRACE 로 남는다. 비밀번호가 그대로 실린다")
				.isEqualTo("warn");
	}

}
