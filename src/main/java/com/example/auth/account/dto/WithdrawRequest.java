package com.example.auth.account.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * 계정 탈퇴 요청. 정본: sp-docs/api-contract.md §2.2.
 *
 * <p><b>필드 이름은 {@code password} 다. {@code currentPassword} 가 아니다</b> (§2.2) —
 * <b>자격증명 필드가 하나면 {@code password}</b> 이고 {@code LoginRequest} 도 그렇다.
 * {@code PATCH /me/password} 만 비밀번호가 <b>둘</b> 있어 구별이 필요해서 {@code currentPassword}
 * 를 쓰며, 그것이 예외다.
 *
 * <p>검증 규칙은 {@link PasswordChangeRequest} 의 {@code currentPassword} 와 같다 —
 * <b>{@code @NotBlank} 만 붙이고 {@code @Pattern} 은 걸지 않는다</b> (§2.2).
 *
 * <ul>
 * <li><b>{@code @Pattern} 금지</b> — 비밀번호 정책이 바뀌면 옛 규칙으로 만든 <b>올바른</b>
 * 비밀번호가 형식 검증에 거부되어, 탈퇴하려는 사용자가 자기 비밀번호를 담은 그 요청에서 막힌다
 * (sp-docs/requirements/member.md §2.1)
 * <li><b>{@code @NotBlank} 요구</b> — 빈 값은 어떤 정책에서도 올바른 비밀번호가 아니므로 잠글
 * 사용자가 없다. 누락은 형식 문제가 아니라 "필드를 보내지 않았다"이고 저장된 비밀번호에 대해
 * 아무것도 드러내지 않는다. 그래서 400 {@code C001} 이고 {@code fieldErrors} 에
 * {@code password} 가 담긴다
 * </ul>
 *
 * <p>값이 틀린 경우는 400 {@code AU004} 이고 {@code AccountService} 가 판정한다.
 * <b>형식으로 가르지 않는다.</b> 두 엔드포인트가 같은 성질의 필드를 같은 코드로 처리한다 (§2.2).
 */
public record WithdrawRequest(

		/*
		 * 메시지는 PasswordChangeRequest 의 것을 그대로 쓴다. 같은 성질의 필드이고
		 * 존재 메시지는 한 군데만 적는다 — PasswordChangeRequest 가 AccountCreateRequest 의
		 * 상수를 쓰는 것과 같은 방식이다
		 */
		@NotBlank(message = PasswordChangeRequest.CURRENT_PASSWORD_MESSAGE)
		String password) {

}
