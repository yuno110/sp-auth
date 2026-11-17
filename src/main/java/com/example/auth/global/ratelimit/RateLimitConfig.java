package com.example.auth.global.ratelimit;

import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 요청 수 제한기와 그 설정을 등록한다 (sp-docs/security.md §10, sp-docs/tech-stack.md §4.6). IP 키를 세는 인터셉터의 등록은
 * {@code global/config/WebConfig} 가 한다.
 *
 * <p>시각은 앱 시계({@code ClockConfig})다 — 테스트가 시계를 바꿔 끼워 창의 경계를 본다.
 */
@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class RateLimitConfig {

	@Bean
	public RateLimiter rateLimiter(RateLimitProperties properties, Clock clock) {
		return new RateLimiter(properties, clock);
	}

}
