package com.example.auth.global.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HexFormat;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

/**
 * IP 키를 센다 (sp-docs/security.md §10). 등록은 {@code global/config/WebConfig} 가 한다.
 *
 * <p><b>CORS 처리 뒤·핸들러 앞이다.</b> MVC 인터셉터라 {@code SecurityConfig} 의 CORS 필터를 지난 뒤에 돈다 — 한도를 넘은
 * 응답에도 CORS 헤더가 실린다. preflight({@code OPTIONS})는 그 필터가 답하고 끝내므로 여기까지 오지 않는다(2026-11-17
 * AU-19 가 spring-web 6.2.19 의 {@code CorsFilter#doFilterInternal} 로 읽었다). 한도를 넘으면 예외를 던져 핸들러에 닿지
 * 않는다 — 로그인이면 비밀번호 비교도 잠금 카운터도 돌지 않는다.
 *
 * <p><b>그 경로에 닿은 요청을 전부 센다.</b> 응답이 성공인지 실패인지 보지 않는다. 본문 검증보다도 앞이다.
 *
 * <p>규칙은 메서드와, 요청을 처리할 핸들러가 매핑된 경로 패턴으로 고른다({@link RateLimitRule#ipRuleOf}). 요청 URI 의 글자를
 * 견주지 않는다 — 퍼센트 인코딩처럼 같은 핸들러에 닿는 다른 표기도 같은 규칙으로 센다.
 */
@Component
@RequiredArgsConstructor
public class RateLimitInterceptor implements HandlerInterceptor {

	/**
	 * IPv6 리터럴의 모양 — 16진 숫자·{@code :}·{@code .} 로만 되어 있고 {@code :} 를 담으며 {@code .} 는 첫 {@code :} 뒤에만
	 * 온다. 이 모양만 {@link InetAddress#getByName} 에 넘긴다. 첫 글자가 16진 숫자나 {@code :} 이고 {@code :} 를 담은
	 * 문자열은 이름 조회(DNS) 없이 리터럴로 읽고, 리터럴이 아니면 조회하지 않고 실패한다 (2026-11-17 AU-19 가 JDK 21 의
	 * {@code InetAddress#getAllByName} 소스로 읽었다).
	 */
	private static final Pattern IPV6_LITERAL = Pattern.compile("[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*");

	private final RateLimiter rateLimiter;

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
		if (request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE) instanceof String pattern) {
			RateLimitRule.ipRuleOf(request.getMethod(), pattern)
					.ifPresent(rule -> this.rateLimiter.consume(rule, ipKeyOf(request.getRemoteAddr())));
		}
		return true;
	}

	/**
	 * IP 키 (sp-docs/security.md §10 의 「키의 주소」). {@code remoteAddr} 만 쓴다 — {@code X-Forwarded-For}·
	 * {@code X-Real-IP} 를 읽지 않는다.
	 *
	 * <ul>
	 *   <li>IPv4 는 주소 그대로다</li>
	 *   <li>IPv6 는 앞 64비트(/64)다. 영역 표기({@code %eth0})는 떼고 읽는다</li>
	 *   <li>IPv4 사상 주소({@code ::ffff:a.b.c.d})는 IPv4 다 — {@link InetAddress} 가 IPv4 주소로 읽는다</li>
	 * </ul>
	 */
	static String ipKeyOf(String remoteAddr) {
		if (remoteAddr.indexOf(':') < 0) {
			return remoteAddr;
		}
		int zone = remoteAddr.indexOf('%');
		InetAddress address = parseIpv6((zone < 0) ? remoteAddr : remoteAddr.substring(0, zone));
		if (address instanceof Inet4Address) {
			return address.getHostAddress();
		}
		return HexFormat.of().formatHex(address.getAddress(), 0, 8) + "/64";
	}

	/** 컨테이너가 준 주소가 IP 가 아니면 세지 못한다. 대신 쓸 키를 지어내지 않고 실패한다. */
	private static InetAddress parseIpv6(String literal) {
		if (!IPV6_LITERAL.matcher(literal).matches()) {
			throw new IllegalStateException("remoteAddr 가 IP 주소가 아니다");
		}
		try {
			return InetAddress.getByName(literal);
		} catch (UnknownHostException e) {
			throw new IllegalStateException("remoteAddr 가 IP 주소가 아니다", e);
		}
	}

}
