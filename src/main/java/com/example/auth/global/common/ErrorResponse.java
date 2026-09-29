package com.example.auth.global.common;

import java.util.List;

// 정본: sp-docs/api-contract.md §7
// 세 서비스가 같은 형식을 갖는 복제 대상이다 (sp-docs/conventions.md §7.1).
// 변경 시 세 서비스를 함께 고친다.
//
// ErrorCode 를 참조하지 않는다. ErrorCode 는 서비스마다 다르고(§7.2) global/error 에 있다.
// 코드·메시지를 채우는 것은 GlobalExceptionHandler 의 몫이다.
public record ErrorResponse(String code, String message, List<FieldError> fieldErrors) {

	public record FieldError(String field, String message) { }

}
