package com.example.auth.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.global.config.FlywayConfig;
import com.example.auth.global.config.JpaConfig;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

/**
 * ADMIN seed 를 검증한다 (sp-docs/plan/phase1.md §4 AU-05 의 "검증" 표 중 seed 네 줄).
 * 값의 정본은 sp-docs/requirements/member.md §10.1, 비밀번호 취급은 §10.2 다.
 *
 * <p><b>이 테스트는 두 스키마 중 auth 쪽만 본다.</b> member 의
 * {@code V2__seed_admin_profile.sql} 과 {@code account_id} 가 같은지는 서비스 둘이 함께
 * 떠 있어야 하므로 통합 검증 I-01 의 몫이다 (sp-docs/plan/integration.md).
 *
 * <p>애노테이션 둘은 sp-docs/conventions.md §9.2 가 요구하는 조합이다.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(JpaConfig.class)
@ActiveProfiles("test")
class AdminSeedTest {

	private static final String SEED_SCRIPT = "db/migration/V3__seed_admin_account.sql";

	/** 가드 검증용 별도 H2 DB. 공유 DB({@code sp_auth})를 건드리지 않는다. */
	private static final String UNRESOLVED_PROBE_URL =
			"jdbc:h2:mem:au05_unresolved_probe;MODE=MySQL;DATABASE_TO_LOWER=TRUE;"
					+ "CASE_INSENSITIVE_IDENTIFIERS=TRUE;DB_CLOSE_DELAY=-1";

	@Autowired
	private TestEntityManager em;

	@Autowired
	private AccountRepository accountRepository;

	/** application-test.yml 이 준 값. 픽스처를 테스트에 다시 적지 않기 위해 주입받는다. */
	@Value("${spring.flyway.placeholders.adminPasswordHash}")
	private String configuredAdminPasswordHash;

	@Test
	@DisplayName("seed 가 적용되고 ADMIN 의 id 가 1, 이메일이 admin@example.com 이다")
	void seed_가_적용되어_있다() {
		Account admin = this.accountRepository.findByEmail("admin@example.com").orElseThrow();

		assertThat(admin.getId())
				.as("member 의 V2 seed 가 account_id 로 참조하는 값이다 (§10.1)")
				.isEqualTo(1L);
		assertThat(admin.getRole()).isEqualTo(Role.ADMIN);
		assertThat(admin.isDeleted()).isFalse();
	}

	@Test
	@DisplayName("SELECT id FROM account WHERE role = 'ADMIN' 이 1 이다")
	void 네이티브_조회로도_1_이다() {
		Object id = this.em.getEntityManager()
				.createNativeQuery("select id from account where role = 'ADMIN'")
				.getSingleResult();

		assertThat(((Number) id).longValue())
				.as("AUTO_INCREMENT 에 맡기면 이 값이 환경마다 달라진다 (§10.1)")
				.isEqualTo(1L);
	}

	/**
	 * <b>여기서 읽는 값은 커밋된 픽스처에서 왔으므로 그 모양을 되읽지 않는다.</b>
	 * {@code application-test.yml} 이 준 값이 그대로 저장된 것이라, 형식을 단언하면 픽스처가
	 * 자기 모양을 되읽는 순환이 되어 실질 정보가 없다 (sp-docs/requirements/member.md §10.2).
	 *
	 * <p>해시 형식은 <b>런타임 생성값</b>에 건다 — 애플리케이션의 {@code PasswordEncoder} 빈이
	 * 대상이고 {@code AccountServiceTest.인코더가_strength_10_해시를_만든다} 가 본다. 런타임
	 * 생성값에 형식을 단언하는 것은 §10.2 의 금지에 해당하지 않는다.
	 *
	 * <p>여기서 보는 것은 <b>치환이 실제로 일어났는가</b>다 — 주입한 값이 그 행에 들어갔는지.
	 */
	@Test
	@DisplayName("seed 의 password 가 주입된 placeholder 값으로 치환되어 저장된다")
	void seed_비밀번호가_치환되어_저장된다() {
		String stored = this.accountRepository.findByEmail("admin@example.com")
				.orElseThrow().getPassword();

		assertThat(stored)
				.as("치환되지 않았으면 ${...} 가 그대로 들어간다")
				.doesNotContain("${")
				.isEqualTo(this.configuredAdminPasswordHash);
	}

	@Test
	@DisplayName("seed SQL 은 해시를 담지 않고 placeholder 를 쓴다")
	void seed_SQL_에_자격증명이_없다() throws IOException {
		String sql = new ClassPathResource(SEED_SCRIPT).getContentAsString(StandardCharsets.UTF_8);

		assertThat(sql)
				.as("해시를 커밋하면 공개 저장소에 ADMIN 자격증명이 남는다 (§10.2)")
				.contains("${adminPasswordHash}")
				.contains("admin@example.com");
		assertThat(bcryptShape().matcher(sql).find())
				.as("V3 에 BCrypt 모양의 문자열이 있으면 해시가 커밋된 것이다")
				.isFalse();
	}

	/**
	 * 저장소 전문 검색 — <b>테스트 픽스처까지 포함해</b> BCrypt 모양이 0건이어야 한다
	 * (sp-docs/requirements/member.md §10.2).
	 *
	 * <p>0건으로 두는 실익은 <b>판별 비용</b>이다. ADMIN seed 값만 막으면 저장소에 "진짜처럼
	 * 보이는 것"과 "가짜"가 섞여, 스캐너 경보마다 사람이 하나씩 판별해야 한다.
	 *
	 * <p>대상은 {@code git ls-files -co --exclude-standard} — 추적 중인 파일과, 추적되지 않은
	 * 파일 중 gitignore 대상이 아닌 것. 그래서 {@code application-local.yml}(실제 해시가 있고
	 * gitignore 대상)과 {@code build/} 는 자동으로 빠진다.
	 */
	@Test
	@DisplayName("저장소 전체에 BCrypt 모양의 문자열이 0건이다")
	void 저장소에_해시_모양이_없다() throws Exception {
		Pattern shape = bcryptShape();
		List<String> hits = new ArrayList<>();

		for (Path file : 저장소의_파일()) {
			// 바이너리(gradle-wrapper.jar)가 섞여 있어 디코딩이 실패하지 않는 방식으로 읽는다.
			// 찾는 것은 ASCII 뿐이라 ISO-8859-1 로 충분하다
			String text = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
			if (shape.matcher(text).find()) {
				hits.add(file.toString());
			}
		}

		assertThat(hits).isEmpty();
	}

	/**
	 * 위 검색이 <b>실제로 돌았는지</b> 본다. 막으려는 것은 스캔이 0개 파일을 보고
	 * {@code isEmpty()} 가 공허하게 통과하는 것이다.
	 *
	 * <p>저장소 작업 트리에 더미 파일을 쓰는 방식으로 확인하지 않는다 — JVM 이 죽으면 잔해가
	 * 남고, 스캔 자체가 미추적 파일을 훑으므로 다른 실행을 깨뜨린다.
	 */
	@Test
	@DisplayName("스캔 자기 점검 — 파일을 수집하고 패턴이 양성 샘플을 잡는다")
	void 스캔_자기_점검() throws Exception {
		assertThat(저장소의_파일())
				.as("0개 파일을 보면 저장소 전문 검색의 isEmpty() 는 아무것도 보증하지 않는다")
				.isNotEmpty();

		// 양성 샘플도 리터럴로 적지 않는다. 조립하면 이 파일이 스캔에 걸리지 않는다
		String positiveSample = "$2" + "a" + "$10$" + "x".repeat(53);

		assertThat(bcryptShape().matcher(positiveSample).find())
				.as("패턴이 양성 샘플을 못 잡으면 스캔은 아무것도 걸러내지 않는다")
				.isTrue();
	}

	private static List<Path> 저장소의_파일() throws Exception {
		Process process = new ProcessBuilder("git", "ls-files", "-co", "--exclude-standard")
				.directory(new File(System.getProperty("user.dir")))
				.start();

		List<Path> files = new ArrayList<>();
		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
			for (String line = reader.readLine(); line != null; line = reader.readLine()) {
				Path path = Path.of(line.trim());
				if (Files.isRegularFile(path)) {
					files.add(path);
				}
			}
		}

		assertThat(process.waitFor(30, TimeUnit.SECONDS)).as("git ls-files 가 끝난다").isTrue();
		assertThat(process.exitValue()).as("git ls-files 종료 코드").isZero();
		assertThat(files).as("목록이 비면 검색이 아무것도 보지 않은 것이다").isNotEmpty();
		return files;
	}

	/**
	 * <b>리터럴이 아니라 문자 클래스로 조립한다.</b> {@code [aby]} 자리에 실제 문자를 적으면 이
	 * 파일 자체가 위 검색에 걸린다 (sp-docs/requirements/member.md §10.2).
	 */
	private static Pattern bcryptShape() {
		return Pattern.compile("\\$2[aby]\\$");
	}

	/**
	 * 테스트 프로파일의 값은 커밋되므로 BCrypt 모양을 쓰지 않는다
	 * (sp-docs/requirements/member.md §10.2). 실제 자격증명이 아니어도 시크릿 스캐너에 걸리고,
	 * "해시를 커밋하지 않는다"고 정한 것과 모양이 같아 읽는 사람이 구분할 수 없다.
	 *
	 * <p>가드는 {@code hasText} 와 {@code "${"} 시작 여부만 보므로 짧은 마커로 충분하다.
	 */
	@Test
	@DisplayName("application-test.yml 의 adminPasswordHash 가 BCrypt 모양이 아니다")
	void 테스트_프로파일_값이_해시_모양이_아니다() {
		assertThat(bcryptShape().matcher(this.configuredAdminPasswordHash).find())
				.as("값: 길이 %d", this.configuredAdminPasswordHash.length())
				.isFalse();
	}

	/**
	 * 완료 기준: {@code ADMIN_PASSWORD_HASH} 없이 기동하면 마이그레이션이 실패한다 — 그 1단계.
	 *
	 * <p>placeholder 를 아예 주지 않은 Flyway 를 <b>별도의 H2 DB</b>에 직접 돌린다. 공유
	 * DB({@code sp_auth})는 건드리지 않는다. 이것으로 <b>V3 가 placeholder 를 요구한다</b>는 것은
	 * 확인되지만, 실제 기동 경로는 2단계({@link #환경변수가_없으면_기동이_실패한다})가 본다.
	 */
	@Test
	@DisplayName("placeholder 를 주지 않으면 Flyway 가 실패한다")
	void placeholder_없이는_마이그레이션이_실패한다() {
		Flyway flyway = Flyway.configure()
				.dataSource("jdbc:h2:mem:au05_placeholder_probe;MODE=MySQL;DATABASE_TO_LOWER=TRUE;"
						+ "CASE_INSENSITIVE_IDENTIFIERS=TRUE;DB_CLOSE_DELAY=-1", "sa", "")
				.locations("classpath:db/migration")
				.load();

		assertThatThrownBy(flyway::migrate)
				.as("기본값을 두면 임의의 해시로 ADMIN 이 생성된 채 배포될 수 있다 (§10.2)")
				.isInstanceOf(FlywayException.class)
				.hasMessageContaining("No value provided for placeholder");
	}

	/**
	 * 같은 완료 기준의 2단계 — <b>실제 기동 경로</b>다.
	 *
	 * <p>Spring 을 거치면 위 1단계처럼 되지 않는다. {@code spring.flyway.placeholders} 는
	 * {@code @ConfigurationProperties} 바인딩이고 Spring 은 해석되지 않은 placeholder 를 리터럴로
	 * 남기므로(sp-docs/tech-stack.md §4.3), 환경변수가 없으면 Flyway 는 <b>문자열
	 * {@code "${ADMIN_PASSWORD_HASH}"} 를 비밀번호로 넣고 성공한다.</b> 측정으로 확인했다.
	 *
	 * <p>그 조용한 성공을 {@link com.example.auth.global.config.FlywayConfig} 가 막는다.
	 * 이 테스트가 깨지면 ADMIN 이 쓸 수 없는 비밀번호로 생성된 채 배포될 수 있다.
	 */
	@Test
	@DisplayName("ADMIN_PASSWORD_HASH 가 없으면 기동이 실패한다")
	void 환경변수가_없으면_기동이_실패한다() {
		new ApplicationContextRunner()
				.withConfiguration(AutoConfigurations.of(
						DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class))
				.withUserConfiguration(FlywayConfig.class)
				.withPropertyValues(
						"spring.datasource.url=" + UNRESOLVED_PROBE_URL,
						"spring.datasource.username=sa",
						"spring.datasource.password=",
						"spring.datasource.driver-class-name=org.h2.Driver",
						// application.yml 과 같은 모양. ADMIN_PASSWORD_HASH 는 환경에 없다
						"spring.flyway.placeholders.adminPasswordHash=${ADMIN_PASSWORD_HASH}")
				.run(context -> {
					assertThat(context)
							.as("가드가 없으면 이 컨텍스트가 그냥 뜨고 ADMIN 비밀번호가 리터럴로 들어간다")
							.hasFailed()
							.getFailure()
							.rootCause()
							.isInstanceOf(IllegalStateException.class)
							.hasMessageContaining("ADMIN_PASSWORD_HASH");

					assertThat(테이블이_있는가(UNRESOLVED_PROBE_URL, "account"))
							.as("가드는 Flyway 빈을 만들 때 돈다 — 마이그레이션이 아예 시작되지 않아야 한다")
							.isFalse();
				});
	}

	/** 컨텍스트가 뜨지 않았으므로 빈에서 DataSource 를 꺼낼 수 없다. 같은 URL 로 직접 붙는다. */
	private static boolean 테이블이_있는가(String url, String table) throws SQLException {
		try (Connection connection = DriverManager.getConnection(url, "sa", "");
				ResultSet tables = connection.getMetaData().getTables(null, null, "%", null)) {
			while (tables.next()) {
				if (table.equalsIgnoreCase(tables.getString("TABLE_NAME"))) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * <b>{@link FlywayConfig} 가 죽은 코드가 되는 때를 알려주는 테스트다.</b> Boot 의 동작을
	 * 재검증하는 것이 아니라 <b>가드의 존재 근거</b>를 지킨다 (AGENTS.md 불변식 11).
	 *
	 * <p>위 {@link #환경변수가_없으면_기동이_실패한다} 와 같은 설정에서 {@code FlywayConfig} 만
	 * 뺐다. 지금은 컨텍스트가 뜨고 {@code account.password} 에 문자열
	 * {@code "${ADMIN_PASSWORD_HASH}"} 가 들어간다 — {@code varchar(60)} 이고 CHECK 제약이 없어
	 * 22자 리터럴이 그대로 통과한다. <b>그래서 가드가 필요하다.</b>
	 *
	 * <p>Boot 가 나중에 미해결 placeholder 를 바인딩에서 거부하게 되면 이 테스트가 깨진다. 그때
	 * {@code FlywayConfig} 는 불필요해지므로 <b>이 테스트의 실패가 그 신호다.</b> 이것이 없으면
	 * 가드는 아무 일도 하지 않으면서 남는다.
	 */
	@Test
	@DisplayName("가드를 빼면 미주입이 조용히 통과한다 — FlywayConfig 의 존재 근거")
	void 가드가_없으면_리터럴이_그대로_저장된다() {
		new ApplicationContextRunner()
				.withConfiguration(AutoConfigurations.of(
						DataSourceAutoConfiguration.class, FlywayAutoConfiguration.class))
				// FlywayConfig 를 넣지 않는다. 이 한 줄이 위 테스트와의 유일한 차이다
				.withPropertyValues(
						"spring.datasource.url=jdbc:h2:mem:au05_unguarded_probe;MODE=MySQL;"
								+ "DATABASE_TO_LOWER=TRUE;CASE_INSENSITIVE_IDENTIFIERS=TRUE;DB_CLOSE_DELAY=-1",
						"spring.datasource.username=sa",
						"spring.datasource.password=",
						"spring.datasource.driver-class-name=org.h2.Driver",
						"spring.flyway.placeholders.adminPasswordHash=${ADMIN_PASSWORD_HASH}")
				.run(context -> {
					assertThat(context)
							.as("Boot 가 미해결 placeholder 를 거부하게 됐다면 FlywayConfig 는 이제 "
									+ "죽은 코드다. 이 단언이 그때를 알린다")
							.hasNotFailed();

					String stored = new JdbcTemplate(context.getBean(DataSource.class))
							.queryForObject("select password from account where id = 1", String.class);

					assertThat(stored)
							.as("마이그레이션이 성공하고 해시가 아닌 리터럴이 들어간다 — ADMIN 계정이 "
									+ "쓸 수 없는 비밀번호로 만들어진 것을 아무도 모른다")
							.isEqualTo("${ADMIN_PASSWORD_HASH}");
				});
	}

}
