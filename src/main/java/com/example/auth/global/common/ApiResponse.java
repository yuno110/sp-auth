package com.example.auth.global.common;

// 정본: sp-docs/api-contract.md §7
// 세 서비스가 같은 형식을 갖는 복제 대상이다 (sp-docs/conventions.md §7.1).
// 변경 시 세 서비스를 함께 고친다.
public record ApiResponse<T>(boolean success, T data, ErrorResponse error) {

	public static <T> ApiResponse<T> success(T data) {
		return new ApiResponse<>(true, data, null);
	}

	public static ApiResponse<Void> failure(ErrorResponse error) {
		return new ApiResponse<>(false, null, error);
	}

}
