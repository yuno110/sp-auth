package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.schemaprobe.SchemaProbeConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.hibernate.tool.schema.spi.SchemaManagementException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.Environment;

/**
 * 테스트 실행 환경 자체를 검증한다 (sp-docs/plan/phase1.md §4 AU-03 의 "검증" 표 마지막 세 줄).
 *
 * <p>여기서 보는 셋은 조용히 어긋나는 것들이라 개별 테스트가 초록이어도 실제로는
 * 검증이 꺼져 있을 수 있다 (sp-docs/tech-stack.md §5).
 *
 * <p><b>{@code @ActiveProfiles} 를 일부러 붙이지 않았다.</b> {@code build.gradle} 의
 * {@code systemProperty 'spring.profiles.active', 'test'} 가 프로파일을 기본값으로 만들었는지
 * 확인하기 위해서다 (sp-docs/tech-stack.md §5.1). 그 한 줄이 사라지면 아래 URL 단언이 깨진다.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class TestDatabaseEnvironmentTest {

	/** sp-docs/tech-stack.md §5.3 의 정본. 스키마만 서비스별로 다르다. */
	private static final String CANONICAL_URL =
			"jdbc:h2:mem:sp_auth;MODE=MySQL;DATABASE_TO_LOWER=TRUE;CASE_INSENSITIVE_IDENTIFIERS=TRUE;DB_CLOSE_DELAY=-1";

	@Autowired
	private DataSource dataSource;

	@Autowired
	private Environment environment;

	@Test
	@DisplayName("테스트가 도는 DataSource URL 이 tech-stack.md §5.3 정본과 문자열까지 같다")
	void 정본_URL_로_돈다() {
		assertThat(dataSource)
				.as("@AutoConfigureTestDatabase(replace = NONE) 이 없으면 jdbc:h2:mem:<uuid> 로 교체된다")
				.isInstanceOf(HikariDataSource.class);

		assertThat(((HikariDataSource) dataSource).getJdbcUrl()).isEqualTo(CANONICAL_URL);
	}

	@Test
	@DisplayName("테이블명이 MySQL 과 같이 소문자로 저장된다")
	void 테이블명이_소문자다() throws Exception {
		List<String> tables = new ArrayList<>();
		try (Connection connection = dataSource.getConnection();
				ResultSet rs = connection.getMetaData()
						.getTables(null, null, "%", new String[] {"TABLE"})) {
			while (rs.next()) {
				tables.add(rs.getString("TABLE_NAME"));
			}
		}

		assertThat(tables)
				.as("DATABASE_TO_LOWER 가 빠지면 ACCOUNT·REFRESH_TOKEN 으로 대문자 저장된다")
				.contains("account", "refresh_token")
				.doesNotContain("ACCOUNT", "REFRESH_TOKEN");
	}

	@Test
	@DisplayName("엔티티에만 있는 컬럼이 있으면 ddl-auto: validate 가 기동을 실패시킨다")
	void 스키마_검증이_적용된다() {
		// (1) 테스트 프로파일이 validate 를 켠다
		assertThat(environment.getProperty("spring.jpa.hibernate.ddl-auto"))
				.as("application-test.yml 의 ddl-auto 가 실제 컨텍스트에 실려 있다")
				.isEqualTo("validate");

		// (2) validate 가 켜져 있으면 엔티티에만 있는 컬럼이 기동을 실패시킨다
		new ApplicationContextRunner()
				.withConfiguration(AutoConfigurations.of(
						DataSourceAutoConfiguration.class,
						FlywayAutoConfiguration.class,
						HibernateJpaAutoConfiguration.class))
				.withUserConfiguration(SchemaProbeConfig.class)
				.withPropertyValues(
						"spring.datasource.url=" + CANONICAL_URL,
						"spring.datasource.username=sa",
						"spring.datasource.password=",
						"spring.datasource.driver-class-name=org.h2.Driver",
						"spring.jpa.hibernate.ddl-auto=validate")
				.run(context -> assertThat(context)
						.as("validate 가 꺼져 있으면(또는 create-drop 이면) 이 컨텍스트가 그냥 뜬다")
						.hasFailed()
						.getFailure()
						.hasRootCauseInstanceOf(SchemaManagementException.class));
	}

}
