package com.example.auth.account.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * 메일 링크의 토큰을 받는 요청 — 이메일 인증 확인. 정본: sp-docs/api-contract.md §2.4.
 *
 * <p><b>{@code @NotBlank} 만 붙인다.</b> 누락·빈 값은 400 {@code C001} 이고 {@code fieldErrors} 에 {@code token} 이
 * 담긴다. <b>형식 검증을 걸지 않는다</b> (§2.4) — 길이·문자 집합이 틀린 토큰은 그냥 맞지 않는 토큰이고 사용 처리가
 * 그것을 400 {@code AU007} 로 끝낸다. 형식으로 {@code C001} 을 내면 토큰의 모양이 응답으로 갈린다.
 */
public record TokenConfirmRequest(

		@NotBlank(message = TOKEN_MESSAGE)
		String token) {

	/**
	 * 존재 메시지다. 정본은 이 필드의 메시지 문구를 정하지 않았다 — {@code fieldErrors} 의 메시지는 정책 설명이 아니라
	 * 「보내지 않았다」 를 말하는 존재 메시지로 둔다 (sp-docs/api-contract.md §2.2 의 {@code currentPassword} 와 같은
	 * 성질, {@code LogoutRequest} 와 같은 방식).
	 */
	static final String TOKEN_MESSAGE = "토큰을 입력해주세요.";

}
