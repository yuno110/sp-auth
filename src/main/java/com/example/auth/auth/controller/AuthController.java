package com.example.auth.auth.controller;

import com.example.auth.auth.dto.LoginRequest;
import com.example.auth.auth.dto.TokenResponse;
import com.example.auth.auth.service.AuthService;
import com.example.auth.global.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 인증 API — 세션·토큰 행위. 정본: sp-docs/api-contract.md §2.1.
 *
 * <p>AU-06 이 만들고 AU-07(재발급·로그아웃)이 확장한다 (sp-docs/plan/phase1.md §2.3).
 *
 * <p>경로별 인가는 AU-04 의 {@code SecurityConfig} 가 선반영했다 — {@code POST /api/v1/auth/login}
 * 은 무인증이다 (sp-docs/security.md §5.1).
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

	private final AuthService authService;

	/**
	 * 로그인. 200 과 {@code TokenResponse} (sp-docs/api-contract.md §2.1 §9.2).
	 *
	 * <p>{@code @Valid} 를 붙이지 않는다 — 이유는 {@link LoginRequest} 에 있다. 실패는 모두
	 * 401 {@code AU003} 이며 {@code GlobalExceptionHandler} 가 공통 형식으로 변환한다.
	 */
	@PostMapping("/login")
	public ApiResponse<TokenResponse> login(@RequestBody LoginRequest request) {
		return ApiResponse.success(this.authService.login(request));
	}

}
