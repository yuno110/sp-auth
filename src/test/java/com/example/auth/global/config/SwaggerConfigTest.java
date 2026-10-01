package com.example.auth.global.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.support.TestRsaKeys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * springdoc 이 OpenAPI 문서를 생성하는지 본다 (AU-02 완료 기준).
 *
 * <p>{@code /swagger-ui.html} 이 <b>인증 없이</b> 열리는 것은 이 항목의 기준이 아니다. 경로를
 * {@code permitAll} 로 여는 SecurityConfig 는 AU-04 의 산출물이므로, 여기서는
 * {@code addFilters = false} 로 필터를 걷고 MVC 계층만 본다. 필터를 포함한 인가 확인은
 * {@code SecurityConfigTest} 가 한다 (sp-docs/security.md §5.1.1).
 */
@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class SwaggerConfigTest {

	/** AU-04 부터 컨텍스트가 개인키를 요구한다. {@code AuthApplicationTest} 와 같은 이유다. */
	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private MockMvc mockMvc;

	@Test
	@DisplayName("springdoc 이 /swagger-ui.html 진입점을 Swagger UI 로 매핑한다")
	void swagger_ui_진입점이_매핑된다() throws Exception {
		mockMvc.perform(get("/swagger-ui.html"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/swagger-ui/index.html"));
	}

	/**
	 * {@code info} 가 SwaggerConfig 의 값이어야 통과한다. springdoc 기본값은
	 * {@code "OpenAPI definition"} 이므로 이 단언이 곧 SwaggerConfig 등록 확인이다.
	 */
	@Test
	@DisplayName("/v3/api-docs 가 SwaggerConfig 의 정보로 OpenAPI 문서를 돌려준다")
	void api_docs_가_문서를_돌려준다() throws Exception {
		mockMvc.perform(get("/v3/api-docs"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.openapi").exists())
				.andExpect(jsonPath("$.info.title").value("auth-service API"))
				.andExpect(jsonPath("$.info.version").value("v1"));
	}

}
