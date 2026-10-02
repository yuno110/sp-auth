package com.example.auth.global.config;

import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.springframework.boot.autoconfigure.flyway.FlywayConfigurationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

/**
 * ADMIN seed 의 비밀번호 해시 주입을 검증한다 (sp-docs/requirements/member.md §10.2).
 *
 * <p><b>이 빈이 없으면 {@code ADMIN_PASSWORD_HASH} 미설정이 조용히 통과한다.</b> 측정 결과다 —
 * {@code spring.flyway.placeholders} 는 {@code @ConfigurationProperties} 로 바인딩되고, Spring 은
 * <b>해석되지 않은 placeholder 를 리터럴로 남긴다</b>(sp-docs/tech-stack.md §4.3). 그래서 환경변수가
 * 없으면 Flyway 가 실패하는 대신 {@code account.password} 에 문자열
 * {@code "${ADMIN_PASSWORD_HASH}"} 가 그대로 들어가고, 마이그레이션은 성공한다. ADMIN 계정이
 * 쓸 수 없는 비밀번호로 만들어진 것을 아무도 모른다.
 *
 * <p>정본은 "주입하지 않으면 마이그레이션이 실패한다"를 요구하므로(§10.2, sp-docs/security.md §7)
 * 그 실패를 여기서 명시적으로 드러낸다. {@code SecurityConfig} 의 CORS 와 {@code JwtConfig} 의
 * 개인키 경로가 쓰는 것과 같은 방식이다 — <b>환경에서 오는 값의 금지 조건은 설정 빈이 지킨다.</b>
 *
 * <p>{@link FlywayConfigurationCustomizer} 를 쓰는 이유는 순서다. 이 콜백은 Flyway 빈을 만들 때
 * 불리므로 {@code migrate()} 보다 반드시 먼저 돈다. 값의 출처(환경변수 / {@code
 * application-local.yml} / {@code application-test.yml})와 무관하게 Flyway 가 실제로 쓸 값을 본다.
 */
@Configuration
public class FlywayConfig {

	/** sp-docs/requirements/member.md §10.2 가 정한 placeholder 이름. */
	private static final String ADMIN_PASSWORD_HASH = "adminPasswordHash";

	@Bean
	public FlywayConfigurationCustomizer adminPasswordHashValidator() {
		return FlywayConfig::validateAdminPasswordHash;
	}

	private static void validateAdminPasswordHash(FluentConfiguration configuration) {
		String hash = configuration.getPlaceholders().get(ADMIN_PASSWORD_HASH);

		// 해석되지 않은 placeholder 는 "${ADMIN_PASSWORD_HASH}" 라는 리터럴로 들어온다
		if (!StringUtils.hasText(hash) || hash.startsWith("${")) {
			throw new IllegalStateException(
					"ADMIN_PASSWORD_HASH 가 없다. ADMIN seed 의 비밀번호 해시는 기본값 없이 외부에서 "
							+ "주입한다 (sp-docs/requirements/member.md §10.2). 로컬에서는 "
							+ "application-local.yml 에 넣고, 해시는 ./gradlew bcrypt -Ppassword=... "
							+ "로 만든다.");
		}
		// 해시 자체는 메시지·로그에 남기지 않는다 (sp-docs/conventions.md §8)
	}

}
