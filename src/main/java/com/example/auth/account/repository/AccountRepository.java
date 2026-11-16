package com.example.auth.account.repository;

import com.example.auth.account.entity.Account;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AccountRepository extends JpaRepository<Account, Long> {

	/** 로그인 ID 는 email 이다 (sp-docs/domain-model.md §2.1). */
	Optional<Account> findByEmail(String email);

	/**
	 * 잠금 읽기({@code SELECT ... FOR UPDATE}). <b>링크 토큰의 확인이 계정을 읽을 때 쓴다</b>
	 * (sp-docs/requirements/member.md §11.2·§11.4).
	 *
	 * <p><b>읽은 행을 엔터티로 고쳐 쓰므로 잠금 읽기다.</b> 엔터티의 변경은 커밋 때 그 행을 읽어 둔 값으로 다시 쓴다
	 * ({@code Account} 에 바뀐 컬럼만 싣는 설정이 없다). 잠그지 않고 읽으면 읽기와 그 쓰기 사이에 커밋된 탈퇴의
	 * {@code deleted} 를 읽어 둔 값으로 덮어 탈퇴한 계정이 되살아난다. 잠금 읽기는 최신 커밋 값을 읽고, 이 트랜잭션이
	 * 끝날 때까지 그 행의 다른 쓰기를 기다리게 한다. 그래서 탈퇴 검사가 본 값이 쓰는 때까지 그대로다. 그 경합은
	 * {@code AccountServiceTest} 가 확인 사이에 탈퇴를 끼워 넣어 본다.
	 *
	 * <p>트랜잭션 안에서만 부른다 — 잠금은 그 트랜잭션이 끝날 때 풀린다.
	 */
	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select a from Account a where a.id = :id")
	Optional<Account> findByIdForUpdate(@Param("id") Long id);

	/**
	 * 이메일 중복 확인용 (sp-docs/api-contract.md §2.2 {@code GET /accounts/check-email}).
	 *
	 * <p>탈퇴한 계정의 행도 남아 있으므로 {@code deleted} 를 조건에 넣지 않는다 — 탈퇴한
	 * 이메일은 재사용할 수 없다 (sp-docs/requirements/member.md §3 규칙 1).
	 */
	boolean existsByEmail(String email);

}
