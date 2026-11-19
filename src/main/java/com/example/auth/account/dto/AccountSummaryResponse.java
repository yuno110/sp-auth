package com.example.auth.account.dto;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import java.time.LocalDateTime;

/**
 * 계정 목록의 원소. 정본: sp-docs/api-contract.md §2.5 의 키 표, 예시는 §9.12.
 *
 * <p><b>비밀번호·인증 시각·잠금 시각을 싣지 않는다</b> — 관리 화면에 필요한 것은 상태다(§2.5). 그래서 인증과 잠금은 시각이
 * 아니라 {@code boolean} 이다. 닉네임도 없다 — member 소유이고 화면이 member 의 일괄 조회로 합친다
 * (sp-docs/requirements/member.md §13). 선언 순서가 JSON 키 순서다.
 *
 * @param id {@code account.id}. member 의 일괄 조회에 넘기는 값이다
 * @param createdAt 오프셋을 표기하지 않는다 (sp-docs/tech-stack.md §6)
 * @param emailVerified {@code email_verified_at} 이 있으면 {@code true}
 * @param locked 그 이메일의 로그인 잠금이 지금 걸려 있으면 {@code true} (sp-docs/domain-model.md §2.5)
 */
public record AccountSummaryResponse(
		Long id,
		String email,
		Role role,
		boolean deleted,
		LocalDateTime createdAt,
		boolean emailVerified,
		boolean locked
) {

	public static AccountSummaryResponse of(Account account, boolean locked) {
		return new AccountSummaryResponse(
				account.getId(),
				account.getEmail(),
				account.getRole(),
				account.isDeleted(),
				account.getCreatedAt(),
				account.getEmailVerifiedAt() != null,
				locked);
	}

}
