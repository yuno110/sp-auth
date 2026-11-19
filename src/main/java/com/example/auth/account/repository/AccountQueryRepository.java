package com.example.auth.account.repository;

import static com.example.auth.account.entity.QAccount.account;

import com.example.auth.account.dto.AccountSearchCondition;
import com.example.auth.account.entity.Account;
import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

/**
 * 계정 목록 (ADMIN). 정본: sp-docs/api-contract.md §2.5. 조건·정렬·페이징을 QueryDSL 로 조합한다.
 *
 * <p>탈퇴한 계정도 대상이다 — {@code deleted} 조건이 없으면 둘 다 싣는다(§2.5). {@code email} 의 부분 일치는 인덱스를 쓰지
 * 않는다(§2.5). 비교의 대소문자 구분은 컬럼의 콜레이션이 정한다.
 */
@Repository
@RequiredArgsConstructor
public class AccountQueryRepository {

	private final JPAQueryFactory queryFactory;

	public Page<Account> search(AccountSearchCondition condition) {
		Pageable pageable = PageRequest.of(condition.page(), condition.size());
		BooleanExpression[] filters = {emailContains(condition), roleEq(condition), deletedEq(condition)};

		List<Account> content = this.queryFactory
				.selectFrom(account)
				.where(filters)
				.orderBy(order(condition))
				.offset(pageable.getOffset())
				.limit(pageable.getPageSize())
				.fetch();

		Long total = this.queryFactory
				.select(account.count())
				.from(account)
				.where(filters)
				.fetchOne();

		return new PageImpl<>(content, pageable, Objects.requireNonNullElse(total, 0L));
	}

	/**
	 * 정렬 키의 끝에 {@code id} 를 둔다 — 동률이 있으면 {@code OFFSET} 페이징이 페이지마다 다른 순서를 받아 같은 행이 두 페이지에
	 * 나오거나 어디에도 안 나온다 (sp-docs/api-contract.md §7.1). {@code id} 의 방향은 앞 키의 방향을 따른다(§2.5).
	 */
	private static OrderSpecifier<?>[] order(AccountSearchCondition condition) {
		return switch (condition.sort()) {
			case latest -> new OrderSpecifier<?>[] {account.createdAt.desc(), account.id.desc()};
			case email -> new OrderSpecifier<?>[] {account.email.asc(), account.id.asc()};
		};
	}

	/** {@code LIKE '%값%'}. QueryDSL 의 {@code contains} 가 값의 {@code %}·{@code _} 를 이스케이프한다. */
	private static BooleanExpression emailContains(AccountSearchCondition condition) {
		return condition.email() == null ? null : account.email.contains(condition.email());
	}

	private static BooleanExpression roleEq(AccountSearchCondition condition) {
		return condition.role() == null ? null : account.role.eq(condition.role());
	}

	private static BooleanExpression deletedEq(AccountSearchCondition condition) {
		return condition.deleted() == null ? null : account.deleted.eq(condition.deleted());
	}

}
