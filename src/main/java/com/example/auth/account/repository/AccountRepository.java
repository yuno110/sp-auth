package com.example.auth.account.repository;

import com.example.auth.account.entity.Account;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository extends JpaRepository<Account, Long> {

	/** 로그인 ID 는 email 이다 (sp-docs/domain-model.md §2.1). */
	Optional<Account> findByEmail(String email);

	/**
	 * 이메일 중복 확인용 (sp-docs/api-contract.md §2.2 {@code GET /accounts/check-email}).
	 *
	 * <p>탈퇴한 계정의 행도 남아 있으므로 {@code deleted} 를 조건에 넣지 않는다 — 탈퇴한
	 * 이메일은 재사용할 수 없다 (sp-docs/requirements/member.md §3 규칙 1).
	 */
	boolean existsByEmail(String email);

}
