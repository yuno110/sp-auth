package com.example.auth.account.entity;

/**
 * 링크 토큰의 목적. 정본: sp-docs/domain-model.md §2.4, sp-docs/requirements/member.md §11.1.
 *
 * <p>{@code account_token.purpose} 에 <b>이름으로</b> 저장한다 ({@code @Enumerated(EnumType.STRING)}).
 * 컬럼이 {@code VARCHAR(20)} 이므로 이름이 20자를 넘으면 저장되지 않는다
 * (sp-docs/domain-model.md §1.2).
 *
 * <p>한 목적의 토큰은 다른 목적의 확인에 쓰이지 않는다 — 사용 처리가 목적을 조건에 넣는다.
 */
public enum TokenPurpose {

	EMAIL_VERIFICATION,

	PASSWORD_RESET

}
