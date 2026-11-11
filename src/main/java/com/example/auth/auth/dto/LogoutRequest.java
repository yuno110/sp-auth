package com.example.auth.auth.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * 로그아웃 요청. 정본: sp-docs/api-contract.md §2.1 §9.5, sp-docs/requirements/member.md §6.4.
 *
 * <p><b>로그아웃을 시작한 세션의 Refresh Token 이다.</b> 계정당 1행이고 행 하나가 세션 하나이므로
 * (sp-docs/domain-model.md §2.2) 이 값이 그 행의 저장값이나 직전 토큰과 같을 때만 행을 지운다.
 * 지울 계정은 이 값이 아니라 검증된 Access Token 의 {@code sub} 가 정한다.
 *
 * <p><b>{@code @NotBlank} 만 붙인다.</b> 없거나 비면 400 {@code C001} 이고 {@code fieldErrors} 에
 * {@code refreshToken} 이 담긴다 (§2.1). 형식(JWT 인지)은 보지 않는다 — 서명도 검증하지 않고
 * 문자열 대조가 판정이므로, JWT 가 아닌 값은 어느 행과도 맞지 않아 204 다.
 * {@link ReissueRequest} 가 검증 애노테이션을 두지 않는 것과 다른 이유는 정본이 재발급에는 400
 * 경로를 두지 않았고 로그아웃에는 두었기 때문이다.
 */
public record LogoutRequest(

		@NotBlank(message = REFRESH_TOKEN_MESSAGE)
		String refreshToken) {

	/**
	 * 존재 메시지다. 정본은 이 필드의 메시지 문구를 정하지 않았다 — {@code fieldErrors} 의
	 * 메시지는 정책 설명이 아니라 "보내지 않았다" 를 말하는 존재 메시지로 둔다
	 * (sp-docs/api-contract.md §2.2 의 {@code currentPassword} 와 같은 성질).
	 */
	static final String REFRESH_TOKEN_MESSAGE = "Refresh Token을 입력해주세요.";

}
