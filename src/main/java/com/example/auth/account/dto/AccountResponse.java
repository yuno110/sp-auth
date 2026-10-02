package com.example.auth.account.dto;

import com.example.auth.account.entity.Account;

/**
 * 계정 생성 응답. 정본: sp-docs/api-contract.md §9.1 — {@code {accountId, email}}.
 *
 * <p><b>{@code password} 를 담지 않는다</b> (sp-docs/requirements/member.md §3 규칙 2).
 * <b>{@code nickname} 도 없다</b> — auth 는 닉네임을 모른다.
 */
public record AccountResponse(Long accountId, String email) {

	public static AccountResponse from(Account account) {
		return new AccountResponse(account.getId(), account.getEmail());
	}

}
