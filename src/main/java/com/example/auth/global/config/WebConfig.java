package com.example.auth.global.config;

import com.example.auth.global.security.CurrentAccountArgumentResolver;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MVC 확장 지점. 지금은 {@code @CurrentAccount} 리졸버 등록 하나다.
 *
 * <p><b>CORS 는 여기가 아니라 {@link SecurityConfig} 에 있다.</b> preflight(OPTIONS)는 인가
 * 필터보다 앞에서 처리돼야 하므로 Security 필터 체인의 CORS 설정을 쓴다. MVC 쪽에만 두면
 * preflight 가 401 로 막힌다.
 */
@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

	private final CurrentAccountArgumentResolver currentAccountArgumentResolver;

	@Override
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
		resolvers.add(this.currentAccountArgumentResolver);
	}

}
