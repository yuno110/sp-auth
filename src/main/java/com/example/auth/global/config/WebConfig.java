package com.example.auth.global.config;

import com.example.auth.global.ratelimit.RateLimitInterceptor;
import com.example.auth.global.security.CurrentAccountArgumentResolver;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MVC 확장 지점 — {@code @CurrentAccount} 리졸버와 요청 수 제한의 IP 키 인터셉터를 등록한다.
 *
 * <p><b>CORS 는 여기가 아니라 {@link SecurityConfig} 에 있다.</b> preflight(OPTIONS)는 인가
 * 필터보다 앞에서 처리돼야 하므로 Security 필터 체인의 CORS 설정을 쓴다. MVC 쪽에만 두면
 * preflight 가 401 로 막힌다.
 *
 * <p>인터셉터는 그 CORS 필터 뒤에 돈다 — IP 키는 CORS 처리 뒤·핸들러 앞에서 센다 (sp-docs/security.md §10).
 */
@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

	private final CurrentAccountArgumentResolver currentAccountArgumentResolver;

	private final RateLimitInterceptor rateLimitInterceptor;

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(this.currentAccountArgumentResolver);
	}

	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(this.rateLimitInterceptor);
	}

}
