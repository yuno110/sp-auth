package com.example.auth.account.repository;

import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.TokenPurpose;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AccountTokenRepository extends JpaRepository<AccountToken, Long> {

	/**
	 * 사용 처리. <b>판정은 조건부 UPDATE 하나다</b> (sp-docs/domain-model.md §2.4,
	 * sp-docs/requirements/member.md §11.1).
	 *
	 * <p>그 해시·그 목적이고, 쓰이지 않았고, 만료 전인 행에 사용 시각을 쓴다. 반환값은 영향 행 수다 —
	 * <b>1 이면 성공이고, 0 이면 없음·만료·사용됨·목적 다름 중 하나다.</b> 그 넷을 가르지 않는다.
	 * 읽어서 확인한 뒤 쓰지 않는다 — 그러면 같은 토큰의 동시 확인 둘이 모두 성공한다.
	 *
	 * <p>시각은 앱 시계의 값을 <b>초로 자른 것</b>이고, 사용 시각과 만료 판정이 같은 값을 쓴다. DB 의
	 * {@code NOW()} 를 쓰지 않는다 (sp-docs/requirements/member.md §11.1).
	 *
	 * <p>탈퇴한 계정은 여기서 가르지 않는다 — 확인이 같은 트랜잭션에서 {@code account.deleted} 를 본다
	 * (sp-docs/requirements/member.md §11.2). 트랜잭션 안에서 부른다.
	 *
	 * <p><b>부르면 영속성 컨텍스트가 flush 되고 비워진다</b>({@link #consumeAt} 의 설정). 앞서 읽은 엔터티는 다시
	 * 읽은 뒤 바꾼다 — 그대로 바꾸면 저장되지 않는다.
	 *
	 * @return 갱신한 행 수. 호출자가 반드시 확인한다
	 */
	default int consume(String tokenHash, TokenPurpose purpose, Clock clock) {
		return consumeAt(tokenHash, purpose, LocalDateTime.now(clock).truncatedTo(ChronoUnit.SECONDS));
	}

	/**
	 * {@link #consume} 의 문장이다. <b>{@link #consume} 으로 부른다</b> — {@code now} 를 초로 자르는
	 * 것은 그쪽이 한다. 자르지 않은 값을 넘기면 MySQL 은 소수부를 반올림하고 H2 는 남겨 두 DB 의
	 * {@code used_at} 저장값이 갈린다 (sp-docs/domain-model.md §1.1).
	 *
	 * <p><b>이 문장은 영속성 컨텍스트를 flush 하고 비운다.</b> 앞서 읽은 엔터티는 준영속이 되어 그 뒤의
	 * 변경이 저장되지 않는다 — 이 문장 뒤에 엔터티를 바꾸려면 다시 읽는다.
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			update AccountToken t
			   set t.usedAt = :now
			 where t.tokenHash = :tokenHash
			   and t.purpose = :purpose
			   and t.usedAt is null
			   and t.expiresAt > :now
			""")
	int consumeAt(@Param("tokenHash") String tokenHash,
			@Param("purpose") TokenPurpose purpose,
			@Param("now") LocalDateTime now);

	/**
	 * 해시로 행을 읽는다. 사용 처리가 1행이면 확인이 이것으로 그 행의 계정 id 를 얻는다.
	 *
	 * <p><b>판정은 사용 처리가 한다.</b> 이 읽기의 결과(만료·사용 여부)로 토큰의 유효성을 판단하지
	 * 않는다 — 읽고 확인한 뒤 쓰는 경로가 된다.
	 */
	Optional<AccountToken> findByTokenHash(String tokenHash);

	/**
	 * 발송 뒤의 지우기 — 같은 계정·같은 목적에서 <b>id 가 새 토큰보다 작은 행</b>을 지운다 (sp-docs/domain-model.md §2.4,
	 * sp-docs/requirements/member.md §11.1). 새 토큰의 메일이 SMTP 에 넘겨진 뒤 발송 작업이 자기 트랜잭션에서 부른다.
	 *
	 * <p>「새 행 말고 전부」 가 아니다 — 겹친 두 발급에서 먼저 끝난 발송이 나중 행, 곧 도착할 메일의 링크를 지우지 않게 한다.
	 * {@code id} 는 IDENTITY 라 나중에 넣은 행이 크다. {@code idx_account_token_account_purpose} 가 이 지우기의 인덱스다
	 * (sp-docs/domain-model.md §2.3).
	 *
	 * @return 지운 행 수
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			delete from AccountToken t
			 where t.accountId = :accountId
			   and t.purpose = :purpose
			   and t.id < :newId
			""")
	int deletePreceding(@Param("accountId") Long accountId,
			@Param("purpose") TokenPurpose purpose,
			@Param("newId") Long newId);

	/**
	 * 확인 뒤의 지우기 — 같은 계정·같은 목적에서 <b>방금 쓴 토큰 말고</b> 나머지 행을 지운다 (sp-docs/domain-model.md §2.4,
	 * sp-docs/requirements/member.md §11.2 의 4·§11.4 의 7). 확인의 트랜잭션 안, 확인의 마지막에 부른다 — 확인이 되돌려지면
	 * 이 지우기도 없다.
	 *
	 * <p>이 문장에서 난 락 예외(교착·대기 시간 초과)를 부르는 쪽이 잡아 삼키지 않는다 — 확인 전체가 되돌려져야 한다
	 * (sp-docs/plan/phase2-auth-member.md AU-24 의 완료 기준 (b)).
	 *
	 * @return 지운 행 수
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			delete from AccountToken t
			 where t.accountId = :accountId
			   and t.purpose = :purpose
			   and t.id <> :usedId
			""")
	int deleteOthers(@Param("accountId") Long accountId,
			@Param("purpose") TokenPurpose purpose,
			@Param("usedId") Long usedId);

	/**
	 * 만료된 행을 지운다 — 정리 작업의 문장이다 (sp-docs/domain-model.md §2.4). 만료는 사용 처리({@link #consumeAt})의
	 * {@code expires_at > now} 가 아닌 것, 곧 {@code expires_at <= now} 다. 지우는 행은 사용 처리가 이미 0행으로 보는
	 * 행뿐이므로 지운 행과 남은 만료 행의 확인 결과가 같다({@code AU007}). 쓰였는지는 보지 않는다 — 쓰였어도 만료 전이면
	 * 남긴다.
	 *
	 * <p>{@code now} 는 앱 시계의 값을 초로 자른 것이다. 트랜잭션 안에서 부른다.
	 *
	 * @return 지운 행 수
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			delete from AccountToken t
			 where t.expiresAt <= :now
			""")
	int deleteExpiredAt(@Param("now") LocalDateTime now);

}
