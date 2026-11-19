package com.example.auth.account.dto;

/**
 * 계정 목록의 정렬. 정본: sp-docs/api-contract.md §2.5.
 *
 * <p>상수 이름이 곧 요청의 {@code sort} 값이다 — 목록에 없는 값은 바인딩이 실패해 400 {@code C002} 다. 컬럼명을 받지 않는다.
 * 각 정렬의 키 순서는 {@code AccountQueryRepository} 가 정하고, 끝에 {@code id} 를 둔다(§7.1).
 */
public enum AccountSortType {

	/** {@code created_at DESC, id DESC}. */
	latest,

	/** {@code email ASC, id ASC}. */
	email

}
