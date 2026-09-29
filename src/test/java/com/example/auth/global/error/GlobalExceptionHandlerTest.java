package com.example.auth.global.error;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.global.common.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * sp-docs/plan/phase1.md §4 AU-02 의 "검증" 표를 테스트로 옮긴 것이다.
 *
 * <p>AU-02 에는 아직 컨트롤러가 없으므로 예외를 던질 대상을 이 테스트 안에 둔다. 중첩 클래스는
 * 컴포넌트 스캔 대상이 아니라 {@code @Import} 로 등록한다. {@code GlobalExceptionHandler} 는
 * {@code @WebMvcTest} 슬라이스가 {@code @RestControllerAdvice} 를 포함하므로 그대로 붙는다.
 *
 * <p>{@code addFilters = false} — SecurityConfig 는 AU-04 의 산출물이므로 지금은 Boot 의
 * 기본 필터 체인이 모든 요청에 인증을 요구한다. 여기서 검증하는 것은 예외 변환이고
 * 경로별 인가는 AU-04 의 {@code SecurityConfigTest} 가 본다.
 */
@WebMvcTest
@Import(GlobalExceptionHandlerTest.ExceptionTestController.class)
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
class GlobalExceptionHandlerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	@DisplayName("BusinessException(AU002) 은 409 와 AU002 로 변환된다")
	void 업무_예외_AU002() throws Exception {
		mockMvc.perform(get("/test/error/email-duplicated"))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").doesNotExist())
				.andExpect(jsonPath("$.error.code").value("AU002"))
				.andExpect(jsonPath("$.error.message").value("이미 사용 중인 이메일입니다."))
				.andExpect(jsonPath("$.error.fieldErrors", hasSize(0)));
	}

	@Test
	@DisplayName("BusinessException(A004) 은 403 과 A004 로 변환된다")
	void 업무_예외_A004() throws Exception {
		mockMvc.perform(get("/test/error/access-denied"))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.error.code").value("A004"))
				.andExpect(jsonPath("$.error.message").value("권한이 없습니다."));
	}

	@Test
	@DisplayName("@Valid 검증 실패는 400 C001 이고 fieldErrors 에 필드별 메시지가 담긴다")
	void 검증_실패는_C001() throws Exception {
		mockMvc.perform(post("/test/valid")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"email\": \"not-an-email\", \"password\": \"\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.message").value("잘못된 입력값입니다."))
				.andExpect(jsonPath("$.error.fieldErrors", hasSize(greaterThan(0))))
				.andExpect(jsonPath("$.error.fieldErrors[*].field").exists())
				.andExpect(jsonPath("$.error.fieldErrors[*].message").exists());
	}

	@Test
	@DisplayName("검증 실패 응답에 입력값이 되돌아오지 않는다")
	void 검증_실패는_입력값을_되돌려주지_않는다() throws Exception {
		MvcResult result = mockMvc.perform(post("/test/valid")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"email\": \"not-an-email\", \"password\": \"s3cr3t-raw-password\"}"))
				.andExpect(status().isBadRequest())
				.andReturn();

		assertThat(result.getResponse().getContentAsString())
				.as("rejectedValue 를 담으면 비밀번호가 응답에 실린다")
				.doesNotContain("s3cr3t-raw-password");
	}

	@Test
	@DisplayName("성공 응답은 success = true 이고 error 가 null 이다")
	void 성공_응답() throws Exception {
		mockMvc.perform(get("/test/success"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.value").value("ok"))
				.andExpect(jsonPath("$.error").isEmpty());
	}

	@Test
	@DisplayName("예상치 못한 RuntimeException 은 500 C005 이고 본문에 스택트레이스·SQL 이 없다")
	void 예상치_못한_예외는_C005() throws Exception {
		MvcResult result = mockMvc.perform(get("/test/error/unexpected"))
				.andExpect(status().isInternalServerError())
				.andExpect(jsonPath("$.error.code").value("C005"))
				.andExpect(jsonPath("$.error.message").value("서버 내부 오류가 발생했습니다."))
				.andReturn();

		assertThat(result.getResponse().getContentAsString())
				.as("예외 메시지를 그대로 내보내면 SQL·내부 정보가 새어 나간다 (§8.4)")
				.doesNotContain("select", "account", "com.example.auth", "java.lang");
	}

	@Test
	@DisplayName("파라미터 타입이 맞지 않으면 400 C002 다")
	void 타입_불일치는_C002() throws Exception {
		mockMvc.perform(get("/test/type-mismatch").param("id", "not-a-number"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error.code").value("C002"))
				.andExpect(jsonPath("$.error.message").value("잘못된 타입의 값입니다."));
	}

	@Test
	@DisplayName("지원하지 않는 HTTP 메서드는 405 C003 이다")
	void 지원하지_않는_메서드는_C003() throws Exception {
		mockMvc.perform(delete("/test/success"))
				.andExpect(status().isMethodNotAllowed())
				.andExpect(jsonPath("$.error.code").value("C003"))
				.andExpect(jsonPath("$.error.message").value("지원하지 않는 HTTP 메서드입니다."));
	}

	@Test
	@DisplayName("매핑되지 않은 경로는 404 C004 다")
	void 없는_경로는_C004() throws Exception {
		mockMvc.perform(get("/test/no-such-path"))
				.andExpect(status().isNotFound())
				.andExpect(jsonPath("$.error.code").value("C004"))
				.andExpect(jsonPath("$.error.message").value("요청한 리소스를 찾을 수 없습니다."));
	}

	@RestController
	@RequestMapping("/test")
	static class ExceptionTestController {

		@GetMapping("/error/email-duplicated")
		void emailDuplicated() {
			throw new BusinessException(ErrorCode.EMAIL_DUPLICATED);
		}

		@GetMapping("/error/access-denied")
		void accessDenied() {
			throw new BusinessException(ErrorCode.ACCESS_DENIED);
		}

		@GetMapping("/error/unexpected")
		void unexpected() {
			throw new IllegalStateException("select password from account where email = 'a@example.com'");
		}

		@GetMapping("/type-mismatch")
		void typeMismatch(@RequestParam Long id) {
		}

		@GetMapping("/success")
		ApiResponse<Payload> success() {
			return ApiResponse.success(new Payload("ok"));
		}

		@PostMapping("/valid")
		ApiResponse<Payload> valid(@Valid @RequestBody SampleRequest request) {
			return ApiResponse.success(new Payload("ok"));
		}

		record Payload(String value) { }

		record SampleRequest(
				@NotBlank @Email String email,
				@NotBlank String password
		) { }

	}

}
