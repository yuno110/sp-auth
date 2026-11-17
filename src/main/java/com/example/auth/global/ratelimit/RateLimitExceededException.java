package com.example.auth.global.ratelimit;

import lombok.Getter;

/**
 * 요청 수 제한을 넘었다. {@code GlobalExceptionHandler} 가 429 {@code C009} 와 {@code Retry-After} 로 바꾼다
 * (sp-docs/security.md §10, sp-docs/conventions.md §6.1).
 *
 * <p>{@code BusinessException} 이 아니다 — 응답에 헤더가 하나 더 붙어 그 일반 경로로 보내지 않는다(같은 §6.1). 센 키(주소·
 * 이메일)를 싣지 않는다. 로그에 남기는 것은 규칙의 이름이다.
 */
@Getter
public class RateLimitExceededException extends RuntimeException {

	private final RateLimitRule rule;

	/** {@code Retry-After} 의 값 — 창이 끝날 때까지 남은 초다. 계산은 {@link RateLimiter} 가 한다. */
	private final long retryAfterSeconds;

	public RateLimitExceededException(RateLimitRule rule, long retryAfterSeconds) {
		super("rate limit exceeded: " + rule.key());
		this.rule = rule;
		this.retryAfterSeconds = retryAfterSeconds;
	}

}
