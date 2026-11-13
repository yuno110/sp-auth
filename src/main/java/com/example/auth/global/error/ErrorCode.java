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
	UNSUPPORTED_MEDIA_TYPE(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "C006", "지원하지 않는 미디어 타입입니다."),
	NOT_ACCEPTABLE(HttpStatus.NOT_ACCEPTABLE, "C007", "응답할 수 있는 형식이 없습니다."),
	// auth 는 multipart 를 받지 않지만 프레임워크가 어느 경로에서든 크기 위반을 던질 수 있어
	// 같은 매핑을 갖는다 (§8.1 의 C008 문단)
	PAYLOAD_TOO_LARGE(HttpStatus.PAYLOAD_TOO_LARGE, "C008", "요청 크기가 허용 한도를 넘었습니다."),
	// 요청 수 제한 초과 (sp-docs/security.md §10). 이 코드로의 매핑은 제한기의 예외와 함께
	// 둔다 (§8.1 의 C009 문단, sp-docs/conventions.md §6.1)
	TOO_MANY_REQUESTS(HttpStatus.TOO_MANY_REQUESTS, "C009", "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요."),

	UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "A001", "인증이 필요합니다."),
	INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "A002", "유효하지 않은 토큰입니다."),
	EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "A003", "만료된 토큰입니다."),
	ACCESS_DENIED(HttpStatus.FORBIDDEN, "A004", "권한이 없습니다."),

	// auth-service — §8.4
	ACCOUNT_NOT_FOUND(HttpStatus.NOT_FOUND, "AU001", "계정을 찾을 수 없습니다."),
	EMAIL_DUPLICATED(HttpStatus.CONFLICT, "AU002", "이미 사용 중인 이메일입니다."),
	LOGIN_FAILED(HttpStatus.UNAUTHORIZED, "AU003", "이메일 또는 비밀번호가 일치하지 않습니다."),
	PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "AU004", "현재 비밀번호가 일치하지 않습니다."),
	// 로그인 잠금. 메시지에 잠금 시간을 적지 않는다 — 값이 바뀌어도 메시지가 거짓이 되지 않게 (§8.4)
	LOGIN_LOCKED(HttpStatus.UNAUTHORIZED, "AU005", "로그인 시도가 많아 잠시 로그인할 수 없습니다."),
	// 비밀번호가 맞은 미인증 계정 (§8.4)
	EMAIL_NOT_VERIFIED(HttpStatus.FORBIDDEN, "AU006", "이메일 인증이 필요합니다."),
	// 메일 링크의 토큰 오류 전부. 사유를 가르지 않는다 (§2.4, §8.4)
	INVALID_LINK_TOKEN(HttpStatus.BAD_REQUEST, "AU007", "링크가 유효하지 않거나 만료되었습니다.");

	private final HttpStatus status;
	private final String code;
	private final String message;

}
