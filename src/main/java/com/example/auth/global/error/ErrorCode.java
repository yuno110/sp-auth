package com.example.auth.global.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

/**
 * 정본: sp-docs/api-contract.md §8.1(공통) §8.4(auth-service).
 *
 * <p>서비스마다 코드가 다르므로 복제하지 않는다 (sp-docs/conventions.md §7.2).
 * 코드를 추가하려면 정본을 먼저 개정한다 (§6).
 *
 * <p>{@code M002}·{@code M004}·{@code M005} 는 auth 로 옮겨와 각각
 * {@code AU002}·{@code AU003}·{@code AU004} 가 됐다. member 는 그 번호를 재사용하지 않으므로
 * 여기에도 두지 않는다 (§8.4).
 */
@Getter
@RequiredArgsConstructor
public enum ErrorCode {

	// 공통 (세 서비스) — §8.1
	INVALID_INPUT_VALUE(HttpStatus.BAD_REQUEST, "C001", "잘못된 입력값입니다."),
	INVALID_TYPE_VALUE(HttpStatus.BAD_REQUEST, "C002", "잘못된 타입의 값입니다."),
	METHOD_NOT_ALLOWED(HttpStatus.METHOD_NOT_ALLOWED, "C003", "지원하지 않는 HTTP 메서드입니다."),
	RESOURCE_NOT_FOUND(HttpStatus.NOT_FOUND, "C004", "요청한 리소스를 찾을 수 없습니다."),
	INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "C005", "서버 내부 오류가 발생했습니다."),

	UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "A001", "인증이 필요합니다."),
	INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "A002", "유효하지 않은 토큰입니다."),
	EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "A003", "만료된 토큰입니다."),
	ACCESS_DENIED(HttpStatus.FORBIDDEN, "A004", "권한이 없습니다."),

	// auth-service — §8.4
	ACCOUNT_NOT_FOUND(HttpStatus.NOT_FOUND, "AU001", "계정을 찾을 수 없습니다."),
	EMAIL_DUPLICATED(HttpStatus.CONFLICT, "AU002", "이미 사용 중인 이메일입니다."),
	LOGIN_FAILED(HttpStatus.UNAUTHORIZED, "AU003", "이메일 또는 비밀번호가 일치하지 않습니다."),
	PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "AU004", "현재 비밀번호가 일치하지 않습니다.");

	private final HttpStatus status;
	private final String code;
	private final String message;

}
