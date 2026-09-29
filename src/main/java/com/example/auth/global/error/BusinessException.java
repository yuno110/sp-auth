package com.example.auth.global.error;

import lombok.Getter;

// 정본: sp-docs/conventions.md §6
// 세 서비스가 같은 형식을 갖는 복제 대상이다 (sp-docs/conventions.md §7.1).
// 변경 시 세 서비스를 함께 고친다.
@Getter
public class BusinessException extends RuntimeException {

	private final ErrorCode errorCode;

	public BusinessException(ErrorCode errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}

}
