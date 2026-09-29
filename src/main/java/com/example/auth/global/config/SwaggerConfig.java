package com.example.auth.global.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// Swagger UI 는 /swagger-ui.html 에 있다 (sp-docs/tech-stack.md §4.4, sp-docs/nfr.md).
// /swagger-ui/** 와 /v3/api-docs/** 를 permitAll 로 여는 것은 AU-04 의 SecurityConfig 이고,
// prod 프로파일에서 springdoc 자체를 끄는 것은 AU-11 이다 (sp-docs/security.md §5.1.1).
@Configuration
public class SwaggerConfig {

	@Bean
	public OpenAPI authServiceOpenApi() {
		return new OpenAPI().info(new Info()
				.title("auth-service API")
				.description("계정과 인증. 이 서비스만 토큰을 발급한다.")
				.version("v1"));
	}

}
