package com.example.auth.global.security;

import com.example.auth.account.entity.Role;

/**
 * 인증된 요청의 주체. 검증된 JWT Claim 에서만 만든다 (sp-docs/api-contract.md §6).
 *
 * <p><b>{@code nickname} 이 없다.</b> Claim 에 없기 때문이다. 닉네임은 member 소유다
 * (sp-docs/conventions.md §1.1).
 *
 * @param accountId {@code sub}. 전역 식별자(= {@code account.id})
 * @param role {@code role} claim
 */
public record LoginAccount(Long accountId, Role role) { }
