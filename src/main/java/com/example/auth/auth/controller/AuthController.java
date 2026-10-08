package com.example.auth.auth.controller;

import com.example.auth.auth.dto.LoginRequest;
import com.example.auth.auth.dto.ReissueRequest;
import com.example.auth.auth.dto.TokenResponse;
import com.example.auth.auth.service.AuthService;
import com.example.auth.global.common.ApiResponse;
import com.example.auth.global.security.CurrentAccount;
import com.example.auth.global.security.LoginAccount;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * 인증 API — 세션·토큰 행위. 정본: sp-docs/api-contract.md §2.1.
 *
 * <p>AU-06 이 만들고 AU-07(재발급·로그아웃)이 확장했다 (sp-docs/plan/phase1.md §2.3).
 *
 * <p>경로별 인가는 AU-04 의 {@code SecurityConfig} 가 선반영했다 — {@code login}·{@code reissue}
 * 는 무인증, {@code logout} 은 인증이다 (sp-docs/security.md §5.1, sp-docs/api-contract.md §2.1).
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

	/**
	 * 토큰 재발급(Rotation). 200 과 {@code TokenResponse} (sp-docs/api-contract.md §2.1).
	 *
	 * <p><b>무인증 경로다.</b> Refresh Token 이 본문으로 오므로 필터가 검증하지 않는다 —
	 * 인증 수단이 그 토큰 자체이고 {@code AuthService} 가 검증한다.
	 *
	 * <p>{@code @Valid} 를 붙이지 않는다 — 이유는 {@link ReissueRequest} 에 있다.
	 */
	@PostMapping("/reissue")
	public ApiResponse<TokenResponse> reissue(@RequestBody ReissueRequest request) {
		return ApiResponse.success(this.authService.reissue(request));
	}

	/**
	 * 로그아웃. <b>204, 본문 없음</b> (sp-docs/api-contract.md §2.1).
	 *
	 * <p><b>인증이 필요하고 본문을 받지 않는다.</b> 지울 대상은 검증된 Access Token 의
	 * {@code sub} 가 정한다 — 본문의 식별자를 신뢰하지 않는다 (sp-docs/security.md §4).
	 */
	@PostMapping("/logout")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void logout(@CurrentAccount LoginAccount loginAccount) {
		this.authService.logout(loginAccount.accountId());
	}

}
