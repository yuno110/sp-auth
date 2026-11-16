package com.example.auth.account.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * 비밀번호 재설정 확인 요청. 정본: sp-docs/api-contract.md §2.4, 비밀번호 규칙은 sp-docs/requirements/member.md §2.
 *
 * <p><b>{@code token} 에는 {@code @NotBlank} 만 붙인다</b> — 이메일 인증 확인({@link TokenConfirmRequest})과 같다. 누락·빈
 * 값은 400 {@code C001} 이고 {@code fieldErrors} 에 {@code token} 이 담긴다. 형식 검증을 걸지 않는다
 * (sp-docs/api-contract.md §2.4) — 길이·문자 집합이 틀린 토큰은 맞지 않는 토큰이고 확인이 400 {@code AU007} 로 끝낸다.
 * 메시지는 {@link TokenConfirmRequest} 의 것을 그대로 쓴다.
 *
 * <p><b>{@code newPassword} 는 비밀번호 규칙이다</b> (sp-docs/requirements/member.md §2·§11.4). 위반은 400 {@code C001}
 * 이고 {@code fieldErrors} 에 {@code newPassword} 가 담긴다. 이 검증은 컨트롤러가 서비스를 부르기 전에 돌므로 <b>토큰을
 * 쓰기 전에</b> 거른다 — 규칙을 어긴 입력이 링크를 소모하지 않는다 (§11.4). 제약은 {@link AccountCreateRequest} 의 상수를
 * 그대로 쓴다 — 같은 규칙을 두 군데 적지 않는다. {@link PasswordChangeRequest} 의 {@code newPassword} 와 같은 제약이다.
 */
public record PasswordResetConfirmRequest(

		@NotBlank(message = TokenConfirmRequest.TOKEN_MESSAGE)
		String token,

		@NotBlank(message = AccountCreateRequest.PASSWORD_MESSAGE)
		@Pattern(regexp = AccountCreateRequest.PASSWORD_PATTERN, message = AccountCreateRequest.PASSWORD_MESSAGE)
		String newPassword) {

}
