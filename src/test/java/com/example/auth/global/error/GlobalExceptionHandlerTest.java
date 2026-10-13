package com.example.auth.global.error;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.auth.global.common.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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
 *
 * <p><b>{@code controllers} 로 슬라이스를 이 테스트의 컨트롤러 하나로 좁힌다.</b> 인자 없는
 * {@code @WebMvcTest} 는 업무 컨트롤러를 <i>전부</i> 올리면서 그 의존(서비스)은 올리지 않으므로,
 * AU-05 이후 컨트롤러가 생길 때마다 이 컨텍스트가 기동에 실패한다. 검증 대상은 예외 변환이고
 * 업무 컨트롤러는 그 대상이 아니다.
 */
@WebMvcTest(controllers = GlobalExceptionHandlerTest.ExceptionTestController.class)
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

	/**
	 * AU-04 에서 고친 것이다. 이 핸들러가 없으면 {@code HttpMessageNotReadableException} 이
	 * 마지막 그물에 걸려 <b>500 {@code C005}</b> 가 됐다 — 클라이언트가 보낸 깨진 본문을 서버
	 * 장애로 보고하는 셈이다.
	 */
	@Test
	@DisplayName("깨진 JSON 본문은 400 C001 이고 본문이 응답에 되돌아오지 않는다")
	void 깨진_본문은_C001() throws Exception {
		MvcResult result = mockMvc.perform(post("/test/valid")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"email\": \"a@example.com\", \"password\": \"s3cr3t-raw-password\""))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C001"))
				.andExpect(jsonPath("$.error.message").value("잘못된 입력값입니다."))
				.andReturn();

		assertThat(result.getResponse().getContentAsString())
				.as("파싱 실패 메시지에는 본문 일부가 들어 있다. 그대로 내보내면 비밀번호가 실린다")
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

	/**
	 * 본문이 있는데 {@code Content-Type} 이 없다 — {@code HttpMediaTypeNotSupportedException}.
	 *
	 * <p><b>클라이언트 오류이므로 415 다</b> (sp-docs/api-contract.md §8.1). 이 핸들러가 없으면
	 * 마지막 그물에 걸려 <b>500 {@code C005}</b> 가 됐다 (실측).
	 */
	@Test
	@DisplayName("본문이 있는데 Content-Type 이 없으면 415 C006 이다")
	void content_type_없음은_C006() throws Exception {
		mockMvc.perform(post("/test/valid")
						.content("{\"email\": \"a@example.com\", \"password\": \"pw-1234\"}"))
				.andExpect(status().isUnsupportedMediaType())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.data").doesNotExist())
				.andExpect(jsonPath("$.error.code").value("C006"))
				.andExpect(jsonPath("$.error.message").value("지원하지 않는 미디어 타입입니다."))
				.andExpect(jsonPath("$.error.fieldErrors", hasSize(0)));
	}

	@Test
	@DisplayName("JSON 이 아닌 Content-Type 도 415 C006 이다")
	void json_이_아닌_content_type_은_C006() throws Exception {
		mockMvc.perform(post("/test/valid")
						.contentType(MediaType.TEXT_PLAIN)
						.content("{\"email\": \"a@example.com\", \"password\": \"pw-1234\"}"))
				.andExpect(status().isUnsupportedMediaType())
				.andExpect(jsonPath("$.error.code").value("C006"))
				.andExpect(jsonPath("$.error.message").value("지원하지 않는 미디어 타입입니다."));
	}

	/**
	 * {@code Accept} 로 JSON 을 받을 수 없다 — {@code HttpMediaTypeNotAcceptableException}.
	 *
	 * <p><b>응답 본문은 JSON 으로 내보낸다.</b> 요청이 받아 주지 않는 형식이지만, 협상에 맡기면
	 * 본문을 쓸 수 없어 이 핸들러의 응답 자체가 다시 실패한다. 공통 형식
	 * (sp-docs/api-contract.md §7)으로 코드를 알려 주는 쪽이 빈 406 보다 쓸모 있다.
	 */
	@Test
	@DisplayName("Accept 로 JSON 을 받을 수 없으면 406 C007 이다")
	void 받을_수_없는_accept_는_C007() throws Exception {
		mockMvc.perform(get("/test/success").accept(MediaType.APPLICATION_XML))
				.andExpect(status().isNotAcceptable())
				.andExpect(jsonPath("$.success").value(false))
				.andExpect(jsonPath("$.error.code").value("C007"))
				.andExpect(jsonPath("$.error.message").value("응답할 수 있는 형식이 없습니다."));
	}

	/**
	 * <b>상태 코드보다 로그가 더 문제다</b> (sp-docs/api-contract.md §8.1). 마지막 그물은
	 * {@code log.error} 로 스택트레이스를 남기므로, 미디어 타입 예외가 거기로 떨어지면 흔한
	 * 클라이언트 실수가 ERROR 경보를 만들고 원인이 서버에 있는 500 과 구별되지 않는다.
	 *
	 * <p>상태 코드는 위 두 테스트가 본다. 여기서는 로그 수준만 본다.
	 */
	@Test
	@DisplayName("미디어 타입 예외 둘은 ERROR 로그를 남기지 않는다")
	void 미디어_타입_예외는_ERROR_로그를_남기지_않는다() throws Exception {
		Logger handlerLogger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
		ListAppender<ILoggingEvent> appender = new ListAppender<>();
		appender.start();
		Level original = handlerLogger.getLevel();
		// 수집 결과가 주변 설정에 좌우되지 않게 수준을 이 테스트 안에서 정한다
		handlerLogger.setLevel(Level.TRACE);
		handlerLogger.addAppender(appender);
		try {
			mockMvc.perform(post("/test/valid").content("{}"));
			mockMvc.perform(get("/test/success").accept(MediaType.APPLICATION_XML));
		} finally {
			handlerLogger.detachAppender(appender);
			handlerLogger.setLevel(original);
			appender.stop();
		}

		assertThat(appender.list)
				.as("둘 다 핸들러에 걸려야 한다. 비어 있으면 로그 수집이 안 된 것이다")
				.hasSize(2);
		assertThat(appender.list)
				.extracting(ILoggingEvent::getLevel)
				.as("클라이언트 실수가 ERROR 경보를 만들면 안 된다")
				.doesNotContain(Level.ERROR);
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
