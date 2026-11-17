package com.example.auth.global.ratelimit;

import java.util.Arrays;
import java.util.Optional;

/**
 * 요청 수 제한의 규칙 (sp-docs/security.md §10 의 표에서 auth 의 줄). 한도와 창은 설정 {@code rate-limit.rules.<키>} 가
 * 준다 (sp-docs/tech-stack.md §4.6).
 *
 * <p>IP 키의 규칙은 메서드와 경로로 고른다 — 경로가 같아도 메서드가 다르면 그 규칙이 아니다. 단, HEAD 는 GET 으로 본다
 * ({@link #ipRuleOf}). 경로는 요청을 처리할 핸들러가 매핑된 패턴이다({@link RateLimitInterceptor}). 이메일 키의 규칙은 경로로
 * 고르지 않는다 — 컨트롤러가 본문 검증 뒤에 센다.
 */
public enum RateLimitRule {

	CHECK_EMAIL("check-email", "GET /api/v1/accounts/check-email"),
	SIGNUP("signup", "POST /api/v1/accounts"),
	PASSWORD_RESET_IP("password-reset-ip", "POST /api/v1/accounts/password-reset"),
	PASSWORD_RESET_EMAIL("password-reset-email", null),
	VERIFICATION_IP("verification-ip", "POST /api/v1/accounts/email-verification"),
	VERIFICATION_EMAIL("verification-email", null),
	LOGIN("login", "POST /api/v1/auth/login");

	private final String key;

	/** IP 키로 세는 요청의 {@code "<메서드> <경로 패턴>"}. 이메일 키의 규칙은 {@code null} 이다. */
	private final String endpoint;

	RateLimitRule(String key, String endpoint) {
		this.key = key;
		this.endpoint = endpoint;
	}

	/** 설정 {@code rate-limit.rules} 아래의 이름. */
	public String key() {
		return this.key;
	}

	/**
	 * 요청을 IP 키로 세는 규칙. 표에 없는 요청은 비어 있다 — 확인({@code …/confirm})과 재발급처럼 정본이 제한하지 않는 요청이다.
	 *
	 * <p><b>HEAD 는 GET 으로 본다.</b> Spring MVC 는 HEAD 를 같은 경로의 GET 핸들러로 보낸다(2026-11-17 AU-19 가
	 * spring-webmvc 6.2.19 의 {@code RequestMethodsRequestCondition#matchRequestMethod} 바이트코드로 읽었다). 그 경로에 닿은
	 * 요청이므로 GET 의 규칙으로 센다 — sp-docs/security.md §10 의 「그 경로에 닿은 요청 전부」 를 그렇게 읽는다(2026-11-17
	 * 오케스트레이터 결정, 정본은 HEAD 를 말하지 않는다). 세지 않으면 HEAD 로 같은 핸들러를 한도 없이 부른다. 그 밖의 메서드는 그 메서드 그대로 고른다.
	 *
	 * @param method 요청의 메서드
	 * @param pattern 요청을 처리할 핸들러가 매핑된 경로 패턴
	 */
	public static Optional<RateLimitRule> ipRuleOf(String method, String pattern) {
		String endpoint = ("HEAD".equals(method) ? "GET" : method) + " " + pattern;
		return Arrays.stream(values()).filter(rule -> endpoint.equals(rule.endpoint)).findFirst();
	}

}
