package com.example.auth.global.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

import com.example.auth.global.config.ClockConfig;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.io.ClassPathResource;

/**
 * 요청 수 제한의 설정 (sp-docs/security.md §10, sp-docs/tech-stack.md §4.6).
 *
 * <p>테스트 프로파일({@code application-test.yml})은 한도를 크게 덮는다. 그래서 정본 값은 {@code application.yml} 만 읽어
 * 본다 — 덮은 값을 보면 {@code application.yml} 의 숫자가 틀려도 모른다.
 */
class RateLimitConfigTest {

	@Test
	@DisplayName("application.yml 의 한도·창이 security.md §10 의 auth 줄이고 버킷 수와 forward-headers-strategy 가 tech-stack §4.6 의 값이다")
	void application_yml_의_정본_값() throws IOException {
		Binder binder = new Binder(ConfigurationPropertySources.from(
				new YamlPropertySourceLoader().load("application.yml", new ClassPathResource("application.yml"))));

		RateLimitProperties properties = binder.bind("rate-limit", RateLimitProperties.class).get();

		assertThat(properties.bucketsPerRule()).isEqualTo(16384);
		assertThat(properties.rules()).containsOnly(
				entry("check-email", 규칙(20, Duration.ofMinutes(1))),
				entry("signup", 규칙(10, Duration.ofHours(1))),
				entry("password-reset-ip", 규칙(5, Duration.ofHours(1))),
				entry("password-reset-email", 규칙(3, Duration.ofHours(1))),
				entry("verification-ip", 규칙(5, Duration.ofHours(1))),
				entry("verification-email", 규칙(3, Duration.ofHours(1))),
				entry("login", 규칙(30, Duration.ofMinutes(1))));
		assertThat(binder.bind("server.forward-headers-strategy", String.class).get())
				.as("X-Forwarded-For 로 remoteAddr 를 바꾸지 않는다 (sp-docs/security.md §10)")
				.isEqualTo("none");
	}

	/**
	 * 규칙의 설정이 빠지면 기동이 실패한다 (sp-docs/plan/phase2-auth-member.md AU-19 의 「기동 가드」). 같은 설정에 그 규칙을
	 * 더하면 뜬다 — 실패가 그 규칙 하나 때문이다.
	 */
	@Test
	@DisplayName("규칙의 설정이 빠지면 기동이 실패하고 메시지가 그 키를 말한다")
	void 규칙의_설정이_빠지면_기동이_실패한다() {
		ApplicationContextRunner runner = new ApplicationContextRunner()
				.withUserConfiguration(RateLimitConfig.class, ClockConfig.class);

		runner.withPropertyValues(설정(RateLimitRule.LOGIN)).run(context -> {
			assertThat(context).hasFailed();
			assertThat(context.getStartupFailure()).rootCause()
					.isInstanceOf(IllegalStateException.class)
					.hasMessageContaining("rate-limit.rules.login ");
		});
		runner.withPropertyValues(설정(null)).run(context -> assertThat(context).hasSingleBean(RateLimiter.class));
	}

	/** 모든 규칙을 한도 1·창 1분으로 준다. {@code missing} 은 빼고 준다. */
	private static String[] 설정(RateLimitRule missing) {
		List<String> values = new ArrayList<>(List.of("rate-limit.buckets-per-rule=16384"));
		for (RateLimitRule rule : RateLimitRule.values()) {
			if (rule != missing) {
				values.add("rate-limit.rules." + rule.key() + ".limit=1");
				values.add("rate-limit.rules." + rule.key() + ".window=PT1M");
			}
		}
		return values.toArray(String[]::new);
	}

	private static RateLimitProperties.Rule 규칙(int limit, Duration window) {
		return new RateLimitProperties.Rule(limit, window);
	}

}
