package com.example.auth.account.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * 이메일 하나만 받는 요청 본문(예: 인증 메일 재발송, 비밀번호 재설정 요청). 정본: sp-docs/api-contract.md §2.4.
 *
 * <p><b>{@code email} 은 생성과 같은 규칙이다</b> (§2.4, sp-docs/requirements/member.md §2). 누락·빈 값·형식·길이
 * 위반은 400 {@code C001} 이고 {@code fieldErrors} 에 {@code email} 이 담긴다. 규칙을 두 군데 적지 않기 위해
 * {@link AccountCreateRequest} 의 상수를 그대로 쓴다 — {@code GET /accounts/check-email} 과 같은 방식이다.
 *
 * <p>그 밖의 입력은 요청 수 제한의 한도 안이면 202, 넘으면 429 {@code C009} 다 — 어느 쪽이든 계정의 상태로 갈리지 않는다
 * (sp-docs/security.md §10). IP 키는 본문 검증보다 앞에서 세므로 그 한도를 넘은 요청은 위반이 있어도 429 다. 이 값으로
 * 계정을 찾는 것은 요청 스레드가 아니라 발급 작업이다 (sp-docs/requirements/member.md §11.3).
 */
public record EmailRequest(

		@NotBlank(message = AccountCreateRequest.EMAIL_MESSAGE)
		@Email(message = AccountCreateRequest.EMAIL_MESSAGE)
		@Size(max = AccountCreateRequest.EMAIL_MAX_LENGTH, message = AccountCreateRequest.EMAIL_MESSAGE)
		String email) {

}
