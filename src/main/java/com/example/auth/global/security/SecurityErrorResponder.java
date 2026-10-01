package com.example.auth.global.security;

import com.example.auth.global.common.ApiResponse;
import com.example.auth.global.common.ErrorResponse;
import com.example.auth.global.error.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/**
 * 필터 체인에서 거부된 요청을 공통 응답 형식으로 바꾼다 (sp-docs/api-contract.md §7).
 *
 * <p>{@code GlobalExceptionHandler}({@code @RestControllerAdvice}) 는 DispatcherServlet 안에서만
 * 동작한다. 인가 거부는 그 앞의 필터에서 일어나므로 여기서 직접 본문을 쓴다. 두 경로가 한 가지
 * 형식을 내보내도록 한 클래스에 묶었다.
 *
 * <table>
 * <tr><th>상황</th><th>코드</th></tr>
 * <tr><td>인증 없이 인증 필요 경로</td><td>401 {@code A001}</td></tr>
 * <tr><td>인증했으나 권한 없음</td><td>403 {@code A004}</td></tr>
 * </table>
 *
 * <p><b>{@code A002}(유효하지 않은 토큰)·{@code A003}(만료된 토큰) 의 구분은 AU-04 의 완료
 * 기준이 아니다.</b> 둘을 가르려면 디코더 실패 원인을 들여다봐야 하는데, 그 분기는 토큰을
 * 다루는 항목(AU-06·AU-07)의 몫이다. 여기서 문자열 매칭으로 추측하지 않는다.
 */
@Component
@RequiredArgsConstructor
public class SecurityErrorResponder implements AuthenticationEntryPoint, AccessDeniedHandler {

	private final ObjectMapper objectMapper;

	@Override
	public void commence(
			HttpServletRequest request,
			HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		write(response, ErrorCode.UNAUTHORIZED);
	}

	@Override
	public void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException {
		write(response, ErrorCode.ACCESS_DENIED);
	}

	private void write(HttpServletResponse response, ErrorCode errorCode) throws IOException {
		// 예외 메시지를 내보내지 않는다. ErrorCode 의 고정 메시지만 쓴다 (sp-docs/api-contract.md §8.4)
		response.setStatus(errorCode.getStatus().value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());

		ErrorResponse error = new ErrorResponse(errorCode.getCode(), errorCode.getMessage(), List.of());
		this.objectMapper.writeValue(response.getWriter(), ApiResponse.failure(error));
	}

}
