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
 * <tr><td>토큰 없이 인증 필요 경로</td><td>401 {@code A001}</td></tr>
 * <tr><td>서명·형식이 잘못된 토큰</td><td>401 {@code A002}</td></tr>
 * <tr><td>만료된 토큰</td><td>401 {@code A003}</td></tr>
 * <tr><td>인증했으나 권한 없음</td><td>403 {@code A004}</td></tr>
 * </table>
 *
 * <p><b>{@code A002}·{@code A003} 의 구분은 AU-07 이 넣었다.</b> AU-04 는 필터 단계의 모든
 * 인증 실패를 {@code A001} 로 냈고, 둘을 가르는 것은 토큰을 다루는 항목에 배정되어 있다
 * (sp-docs/plan/phase1.md §2.5, §4 AU-07). 판정은 {@link JwtTokenProvider#failureCode} 하나이며
 * 재발급 경로(본문의 Refresh Token)와 같은 것을 쓴다 — <b>문자열 매칭으로 추측하지 않는다.</b>
 */
@Component
@RequiredArgsConstructor
public class SecurityErrorResponder implements AuthenticationEntryPoint, AccessDeniedHandler {

	private final ObjectMapper objectMapper;

	/**
	 * 인증 실패. <b>토큰 없음({@code A001})·유효하지 않음({@code A002})·만료({@code A003}) 를
	 * 가른다</b> (sp-docs/api-contract.md §8.1, sp-docs/plan/phase1.md §4 AU-07).
	 *
	 * <p>Access Token 은 헤더로 오므로 필터 체인이 검증하고 실패가 여기로 온다. 본문으로 오는
	 * Refresh Token 은 {@code AuthService} 가 같은 판정으로 처리한다.
	 */
	@Override
	public void commence(
			HttpServletRequest request,
			HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		write(response, JwtTokenProvider.failureCode(authException));
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
