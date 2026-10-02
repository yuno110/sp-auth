package com.example.auth.global.error;

import com.example.auth.global.common.ApiResponse;
import com.example.auth.global.common.ErrorResponse;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * 정본: sp-docs/api-contract.md §7 §8, sp-docs/conventions.md §6.
 *
 * <p>서비스별 {@link ErrorCode} 에 의존하므로 복제하지 않는다
 * (sp-docs/conventions.md §7.2).
 *
 * <p>응답 본문에 스택트레이스·SQL·내부 호스트명을 넣지 않는다 (§8.4). 그래서 예외 메시지를
 * 그대로 내보내지 않고 {@code ErrorCode} 의 고정 메시지만 쓴다.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(BusinessException.class)
	public ResponseEntity<ApiResponse<Void>> handleBusinessException(BusinessException e) {
		ErrorCode errorCode = e.getErrorCode();
		log.warn("business exception: {}", errorCode.getCode());
		return toResponse(errorCode);
	}

	/** {@code @Valid} 검증 실패. 필드별 메시지를 {@code fieldErrors} 에 담는다. */
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiResponse<Void>> handleMethodArgumentNotValid(MethodArgumentNotValidException e) {
		// rejectedValue 는 담지 않는다. 비밀번호가 그대로 응답·로그에 실린다
		// (sp-docs/conventions.md §8, sp-docs/security.md §7).
		List<ErrorResponse.FieldError> fieldErrors = e.getBindingResult().getFieldErrors().stream()
				.map(fieldError -> new ErrorResponse.FieldError(fieldError.getField(), fieldError.getDefaultMessage()))
				.toList();
		log.warn("validation failed: {} field(s)", fieldErrors.size());
		return toResponse(ErrorCode.INVALID_INPUT_VALUE, fieldErrors);
	}

	/**
	 * 본문을 읽을 수 없을 때 — 깨진 JSON, 빈 본문, 타입이 맞지 않는 필드.
	 *
	 * <p><b>클라이언트 오류이므로 400 이다.</b> 이 핸들러가 없으면 마지막 그물에 걸려
	 * 500 {@code C005} 가 되고, 클라이언트가 보낸 잘못된 본문이 서버 장애로 보고된다.
	 */
	@ExceptionHandler(HttpMessageNotReadableException.class)
	public ResponseEntity<ApiResponse<Void>> handleHttpMessageNotReadable(HttpMessageNotReadableException e) {
		// 예외 메시지에 본문 일부(비밀번호일 수 있다)가 들어 있으므로 로그에도 남기지 않는다
		log.warn("request body not readable");
		return toResponse(ErrorCode.INVALID_INPUT_VALUE);
	}

	/**
	 * 메서드 파라미터 검증 실패 — {@code @RequestParam} 에 걸린 제약이 깨졌다
	 * ({@code GET /accounts/check-email} 의 {@code email} 형식·길이).
	 *
	 * <p><b>클라이언트 오류이므로 400 이다.</b> 이 핸들러가 없으면 마지막 그물에 걸려
	 * 500 {@code C005} 가 된다. 본문 검증({@link MethodArgumentNotValidException})과 같은
	 * 형태로 {@code fieldErrors} 를 채운다.
	 */
	@ExceptionHandler(HandlerMethodValidationException.class)
	public ResponseEntity<ApiResponse<Void>> handleHandlerMethodValidation(HandlerMethodValidationException e) {
		// 여기도 rejectedValue 를 담지 않는다 (sp-docs/api-contract.md §7)
		List<ErrorResponse.FieldError> fieldErrors = e.getParameterValidationResults().stream()
				.flatMap(result -> result.getResolvableErrors().stream()
						.map(error -> new ErrorResponse.FieldError(
								result.getMethodParameter().getParameterName(), error.getDefaultMessage())))
				.toList();
		log.warn("parameter validation failed: {} field(s)", fieldErrors.size());
		return toResponse(ErrorCode.INVALID_INPUT_VALUE, fieldErrors);
	}

	/**
	 * 필수 쿼리 파라미터가 빠진 경우 — {@code GET /accounts/check-email} 에 {@code email} 이 없다.
	 *
	 * <p><b>클라이언트 오류이므로 400 이다.</b> 이 핸들러가 없으면 마지막 그물에 걸려
	 * 500 {@code C005} 가 된다. {@code @RequestParam} 을 쓰는 첫 경로가 AU-05 에서 생겼다.
	 */
	@ExceptionHandler(MissingServletRequestParameterException.class)
	public ResponseEntity<ApiResponse<Void>> handleMissingServletRequestParameter(
			MissingServletRequestParameterException e) {
		log.warn("missing request parameter: {}", e.getParameterName());
		return toResponse(ErrorCode.INVALID_INPUT_VALUE);
	}

	@ExceptionHandler(MethodArgumentTypeMismatchException.class)
	public ResponseEntity<ApiResponse<Void>> handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException e) {
		log.warn("type mismatch on parameter: {}", e.getName());
		return toResponse(ErrorCode.INVALID_TYPE_VALUE);
	}

	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	public ResponseEntity<ApiResponse<Void>> handleHttpRequestMethodNotSupported(
			HttpRequestMethodNotSupportedException e) {
		log.warn("method not allowed: {}", e.getMethod());
		return toResponse(ErrorCode.METHOD_NOT_ALLOWED);
	}

	@ExceptionHandler(NoResourceFoundException.class)
	public ResponseEntity<ApiResponse<Void>> handleNoResourceFound(NoResourceFoundException e) {
		log.warn("no handler for: {}", e.getResourcePath());
		return toResponse(ErrorCode.RESOURCE_NOT_FOUND);
	}

	/** 마지막 그물. 여기까지 온 것은 예상하지 못한 예외이므로 서버 로그에만 원인을 남긴다. */
	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiResponse<Void>> handleException(Exception e) {
		log.error("unhandled exception", e);
		return toResponse(ErrorCode.INTERNAL_SERVER_ERROR);
	}

	private ResponseEntity<ApiResponse<Void>> toResponse(ErrorCode errorCode) {
		return toResponse(errorCode, List.of());
	}

	private ResponseEntity<ApiResponse<Void>> toResponse(
			ErrorCode errorCode, List<ErrorResponse.FieldError> fieldErrors) {
		ErrorResponse error = new ErrorResponse(errorCode.getCode(), errorCode.getMessage(), fieldErrors);
		return ResponseEntity.status(errorCode.getStatus()).body(ApiResponse.failure(error));
	}

}
