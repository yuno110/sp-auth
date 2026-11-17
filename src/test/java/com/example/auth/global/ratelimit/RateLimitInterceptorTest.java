package com.example.auth.global.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerMapping;

/**
 * IP 키 인터셉터의 단위 테스트 — 키를 만드는 법과 규칙을 고르는 법 (sp-docs/security.md §10, sp-docs/plan/phase2-auth-member.md
 * AU-19 의 검증 표).
 *
 * <p>요청은 핸들러 매핑이 남기는 경로 패턴을 직접 싣는다. 실제 경로를 지나 세는지는 {@code RateLimitControllerTest} 가 본다.
 */
class RateLimitInterceptorTest {

	// --- IP 키 (sp-docs/security.md §10 의 「키의 주소」) ---

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"203.0.113.7", "198.51.100.23"})
	@DisplayName("IPv4 는 주소 그대로다")
	void IPv4_는_주소_그대로다(String remoteAddr) {
		assertThat(RateLimitInterceptor.ipKeyOf(remoteAddr)).isEqualTo(remoteAddr);
	}

	@ParameterizedTest(name = "{0} = {1}")
	@CsvSource({
			"2001:db8:a:b::1, 2001:db8:a:b:ffff:ffff:ffff:ffff",
			// 같은 주소의 다른 표기
			"2001:db8:a:b::2, 2001:0db8:000a:000b:0000:0000:0000:0002",
			// 뒤 64비트(인터페이스 식별자)의 첫 비트만 다르다
			"2001:db8::, 2001:db8:0:0:8000::",
			// 영역 표기는 떼고 읽는다
			"fe80::1%eth0, fe80::2%1"
	})
	@DisplayName("같은 /64 의 IPv6 주소는 한 키다")
	void 같은_64_의_IPv6_는_한_키다(String one, String other) {
		assertThat(RateLimitInterceptor.ipKeyOf(other)).isEqualTo(RateLimitInterceptor.ipKeyOf(one));
	}

	@ParameterizedTest(name = "{0} ≠ {1}")
	@CsvSource({
			// 앞 64비트의 마지막 비트만 다르다
			"2001:db8::, 2001:db8:0:1::",
			"2001:db8:a:b::1, 2001:db8:a:c::1",
			"2001:db8::1, 2001:db9::1"
	})
	@DisplayName("/64 가 다른 IPv6 주소는 다른 키다")
	void 다른_64_의_IPv6_는_다른_키다(String one, String other) {
		assertThat(RateLimitInterceptor.ipKeyOf(other)).isNotEqualTo(RateLimitInterceptor.ipKeyOf(one));
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"::ffff:203.0.113.7", "::ffff:cb00:7107", "0:0:0:0:0:ffff:203.0.113.7"})
	@DisplayName("IPv4 사상 주소는 그 IPv4 주소와 같은 키다")
	void IPv4_사상_주소는_IPv4_와_같은_키다(String mapped) {
		assertThat(RateLimitInterceptor.ipKeyOf(mapped)).isEqualTo(RateLimitInterceptor.ipKeyOf("203.0.113.7"));
	}

	/** 컨테이너가 IP 가 아닌 주소를 주면 세지 못한다. 대신 쓸 키를 지어내지 않는다. */
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"2001:db8::zz", "not:an:address", "1:2:3", ":::", "%eth0:"})
	@DisplayName("IPv6 리터럴이 아닌 주소는 키를 만들지 않고 실패한다")
	void IPv6_리터럴이_아니면_실패한다(String remoteAddr) {
		assertThatThrownBy(() -> RateLimitInterceptor.ipKeyOf(remoteAddr)).isInstanceOf(IllegalStateException.class);
	}

	// --- 규칙 고르기 — 메서드와 경로 (sp-docs/security.md §10 의 표) ---

	static Stream<Arguments> 세는_요청() {
		return Stream.of(
				Arguments.of("GET", "/api/v1/accounts/check-email", RateLimitRule.CHECK_EMAIL),
				// HEAD 는 같은 경로의 GET 으로 본다 (RateLimitRule#ipRuleOf)
				Arguments.of("HEAD", "/api/v1/accounts/check-email", RateLimitRule.CHECK_EMAIL),
				Arguments.of("POST", "/api/v1/accounts", RateLimitRule.SIGNUP),
				Arguments.of("POST", "/api/v1/accounts/password-reset", RateLimitRule.PASSWORD_RESET_IP),
				Arguments.of("POST", "/api/v1/accounts/email-verification", RateLimitRule.VERIFICATION_IP),
				Arguments.of("POST", "/api/v1/auth/login", RateLimitRule.LOGIN));
	}

	@ParameterizedTest(name = "{0} {1} → {2}")
	@MethodSource("세는_요청")
	@DisplayName("표의 요청은 그 규칙으로 센다 — 한도 1 에서 두 번째가 그 규칙으로 넘는다")
	void 표의_요청은_그_규칙으로_센다(String method, String pattern, RateLimitRule rule) {
		RateLimitInterceptor interceptor = new RateLimitInterceptor(한도_1의_제한기());

		assertThatCode(() -> interceptor.preHandle(요청(method, pattern, "203.0.113.7"), 응답(), new Object()))
				.doesNotThrowAnyException();
		RateLimitExceededException exceeded = catchThrowableOfType(RateLimitExceededException.class,
				() -> interceptor.preHandle(요청(method, pattern, "203.0.113.7"), 응답(), new Object()));
		assertThat(exceeded).isNotNull();
		assertThat(exceeded.getRule()).isEqualTo(rule);
	}

	/**
	 * 확인({@code …/confirm})과 재발급은 정본이 제한하지 않는다 (sp-docs/security.md §10). 같은 경로라도 메서드가 다르면 표의
	 * 요청이 아니다 — {@code GET /api/v1/accounts} 는 AU-20 이 만들 계정 목록의 경로이고, 그 경로의 {@code POST} 만 가입이다.
	 * AU-19 시점에는 그 목록의 핸들러가 없어 메서드로 고르는 것을 이 단위 테스트로 본다 (sp-docs/plan/phase2-auth-member.md
	 * AU-19 의 검증 표). HEAD 는 GET 으로 볼 뿐이라 GET 의 규칙이 없는 경로의 HEAD 는 세지 않고, OPTIONS 는 GET 으로
	 * 보지 않는다.
	 */
	@ParameterizedTest(name = "{0} {1}")
	@CsvSource({
			"GET, /api/v1/accounts",
			"POST, /api/v1/accounts/email-verification/confirm",
			"POST, /api/v1/accounts/password-reset/confirm",
			"POST, /api/v1/auth/reissue",
			"POST, /api/v1/auth/logout",
			"GET, /api/v1/accounts/me",
			"PATCH, /api/v1/accounts/me/password",
			"DELETE, /api/v1/accounts/me",
			"GET, /api/v1/auth/login",
			"HEAD, /api/v1/auth/login",
			"OPTIONS, /api/v1/auth/login",
			"OPTIONS, /api/v1/accounts/check-email",
			"POST, /api/v1/accounts/check-email"
	})
	@DisplayName("표에 없는 요청은 세지 않는다 — 한도 1 에서 몇 번이든 넘지 않는다")
	void 표에_없는_요청은_세지_않는다(String method, String pattern) {
		RateLimitInterceptor interceptor = new RateLimitInterceptor(한도_1의_제한기());

		for (int i = 0; i < 3; i++) {
			assertThatCode(() -> interceptor.preHandle(요청(method, pattern, "203.0.113.7"), 응답(), new Object()))
					.doesNotThrowAnyException();
		}
	}

	/** 클라이언트가 임의로 쓰는 헤더라 믿으면 요청마다 주소를 바꿔 제한을 비켜 간다 (sp-docs/security.md §10). */
	@Test
	@DisplayName("X-Forwarded-For·X-Real-IP 를 읽지 않는다 — 헤더가 달라도 remoteAddr 가 같으면 한 키다")
	void 전달_헤더를_읽지_않는다() {
		RateLimitInterceptor interceptor = new RateLimitInterceptor(한도_1의_제한기());
		MockHttpServletRequest first = 요청("POST", "/api/v1/auth/login", "203.0.113.7");
		first.addHeader("X-Forwarded-For", "198.51.100.1");
		first.addHeader("X-Real-IP", "198.51.100.1");
		MockHttpServletRequest second = 요청("POST", "/api/v1/auth/login", "203.0.113.7");
		second.addHeader("X-Forwarded-For", "198.51.100.2");
		second.addHeader("X-Real-IP", "198.51.100.2");

		interceptor.preHandle(first, 응답(), new Object());
		assertThatThrownBy(() -> interceptor.preHandle(second, 응답(), new Object()))
				.isInstanceOf(RateLimitExceededException.class);
	}

	/** 핸들러 매핑이 남기는 것과 같은 모양 — 메서드, 그 핸들러가 매핑된 경로 패턴, 주소. */
	private static MockHttpServletRequest 요청(String method, String pattern, String remoteAddr) {
		MockHttpServletRequest request = new MockHttpServletRequest(method, pattern);
		request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, pattern);
		request.setRemoteAddr(remoteAddr);
		return request;
	}

	private static MockHttpServletResponse 응답() {
		return new MockHttpServletResponse();
	}

	/** 모든 규칙의 한도가 1 이고 창이 1시간이다. 시계는 멈춰 있다. */
	private static RateLimiter 한도_1의_제한기() {
		Map<String, RateLimitProperties.Rule> rules = Arrays.stream(RateLimitRule.values())
				.collect(Collectors.toMap(RateLimitRule::key, rule -> new RateLimitProperties.Rule(1, Duration.ofHours(1))));
		return new RateLimiter(new RateLimitProperties(16384, rules),
				Clock.fixed(Instant.parse("2031-03-04T01:00:00Z"), ZoneId.of("Asia/Seoul")));
	}

}
