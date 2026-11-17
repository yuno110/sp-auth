package com.example.auth.global.ratelimit;

import java.time.Duration;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code rate-limit.*} (sp-docs/tech-stack.md §4.6). 한도·창·버킷 수는 정본 값이라 {@code application.yml} 이 적는다.
 *
 * <p>값의 검사는 여기서 하지 않는다 — {@link RateLimiter} 가 만들어질 때 빠진 값과 양수가 아닌 값을 막는다. 그래서 빠진
 * 값이 {@code 0} 이 아니라 {@code null} 로 오도록 래퍼 타입을 쓴다.
 *
 * @param bucketsPerRule 규칙마다 둘 카운터 배열의 크기
 * @param rules {@link RateLimitRule#key()} 마다의 한도와 창
 */
@ConfigurationProperties("rate-limit")
public record RateLimitProperties(Integer bucketsPerRule, Map<String, Rule> rules) {

	/**
	 * @param limit 한 창에서 한 버킷이 받는 요청 수
	 * @param window 창의 길이
	 */
	public record Rule(Integer limit, Duration window) {
	}

}
