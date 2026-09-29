package com.example.auth.account.entity;

// 정본: sp-docs/domain-model.md §2.1 (account.role)
// 문자열로 저장한다. ORDINAL 금지 (sp-docs/domain-model.md §1.2).
public enum Role {

	USER,
	ADMIN

}
