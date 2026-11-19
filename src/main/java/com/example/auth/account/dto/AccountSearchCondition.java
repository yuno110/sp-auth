package com.example.auth.account.dto;

import com.example.auth.account.entity.Role;

/**
 * 계정 목록의 조건. 정본: sp-docs/api-contract.md §2.5.
 *
 * <p>요청의 날값을 여기서 한 번만 정규화한다 — 기본값 채우기는 {@link #of} 가, {@code size} 절삭과 공백만인 {@code email}
 * 을 「없음」 으로 바꾸는 것은 정규 생성자가 한다. 생성자에 두면 어느 경로로 만들어도 거친다.
 *
 * <p><b>하한 위반({@code page} 음수·{@code size} 1 미만)과 {@code email} 의 길이 초과는 여기서 거르지 않는다.</b> 정본이 그
 * 응답을 400 {@code C001} 과 {@code fieldErrors} 1건으로 정했으므로 담을 파라미터 이름을 아는 자리 — {@code AccountController}
 * 의 파라미터 제약 — 에서 거른다. 범위 값은 여기의 상수를 쓴다.
 *
 * @param page 0부터
 * @param size 최대 {@value #MAX_SIZE}. 초과분은 절삭한다
 * @param sort 화이트리스트 enum
 * @param email 부분 일치. {@code null} 이면 조건이 없다
 * @param role {@code null} 이면 조건이 없다
 * @param deleted {@code null} 이면 탈퇴 여부와 상관없이 둘 다
 */
public record AccountSearchCondition(
		int page,
		int size,
		AccountSortType sort,
		String email,
		Role role,
		Boolean deleted
) {

	/** 전달되지 않았을 때의 값 (sp-docs/api-contract.md §2.5). */
	public static final int DEFAULT_PAGE = 0;

	/** 전달되지 않았을 때의 값 (sp-docs/api-contract.md §2.5). */
	public static final int DEFAULT_SIZE = 20;

	/** 전달되지 않았을 때의 값 (sp-docs/api-contract.md §2.5). */
	public static final AccountSortType DEFAULT_SORT = AccountSortType.latest;

	/** 허용 하한. 집행은 {@code AccountController} 의 파라미터 제약이다. */
	public static final int MIN_PAGE = 0;

	/** 허용 하한. 집행은 {@code AccountController} 의 파라미터 제약이다. */
	public static final int MIN_SIZE = 1;

	/** 허용 상한. 넘으면 오류가 아니라 이 값으로 절삭한다 (sp-docs/api-contract.md §2.5). */
	public static final int MAX_SIZE = 50;

	/** {@code email} 의 최대 길이. 넘으면 400 {@code C001} 이다. 집행은 {@code AccountController} 의 파라미터 제약이다. */
	public static final int EMAIL_MAX_LENGTH = 100;

	public AccountSearchCondition {
		size = Math.min(size, MAX_SIZE);
		// 공백만이면 없음으로 본다 (§2.5). 공백이 아닌 값은 그대로 부분 일치에 쓴다
		email = (email == null || email.isBlank()) ? null : email;
	}

	/** 전달되지 않은 파라미터에 §2.5 의 기본값을 채운다. {@code email}·{@code role}·{@code deleted} 는 기본값이 없다. */
	public static AccountSearchCondition of(
			Integer page, Integer size, AccountSortType sort, String email, Role role, Boolean deleted) {

		return new AccountSearchCondition(
				page == null ? DEFAULT_PAGE : page,
				size == null ? DEFAULT_SIZE : size,
				sort == null ? DEFAULT_SORT : sort,
				email,
				role,
				deleted);
	}

}
