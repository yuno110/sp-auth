package com.example.auth.account.dto;

import com.example.auth.account.entity.Account;
import java.time.LocalDateTime;

/**
 * 내 계정 조회 응답. 정본: sp-docs/api-contract.md §2.2 (MR-07 의 계정 절반,
 * sp-docs/requirements/member.md §5).
 *
 * <p><b>{@code accountId} 를 넣지 않는다</b> (§2.2). 식별자가 필요한 클라이언트는 계정 생성
 * 응답이나 member 의 {@code GET /api/v1/members/me} 에서 이미 받는다. 필드를 <b>나중에 더하는
 * 것은 호환되지만 빼는 것은 아니므로</b>, 요구가 생길 때 더한다.
 *
 * <p><b>{@code password} 를 넣지 않는다</b> (sp-docs/security.md §7,
 * sp-docs/requirements/member.md §3 규칙 2). <b>{@code nickname} 도 없다</b> — auth 가 소유하지
 * 않는 값이다 (sp-docs/adr/0012-auth-as-separate-service.md). 닉네임이 필요한 화면은
 * {@code GET /api/v1/members/me} 를 함께 호출한다.
 *
 * <p>{@code record} 이므로 직렬화되는 키 집합이 컴포넌트 목록과 같다 — 응답 형태를 고정하는
 * 지점이 여기 하나다 (sp-docs/conventions.md §3).
 *
 * @param createdAt {@code account.created_at}. {@code LocalDateTime} 이므로 오프셋이 표기되지
 *         않는다 (sp-docs/tech-stack.md §6)
 */
public record AccountMeResponse(String email, LocalDateTime createdAt) {

	public static AccountMeResponse from(Account account) {
		return new AccountMeResponse(account.getEmail(), account.getCreatedAt());
	}

}
