package com.example.auth.auth.repository;

import com.example.auth.auth.entity.LoginAttempt;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

	/** 키로 읽는다. 키는 {@link LoginAttempt#emailKeyOf(String)} 로 만든다. */
	Optional<LoginAttempt> findByEmailKey(String emailKey);

	/**
	 * 카운터를 0 으로 하고 잠금을 푼다. 비밀번호가 맞았을 때와 비밀번호 재설정 확인의 문장이다
	 * (sp-docs/domain-model.md §2.5, sp-docs/requirements/member.md §12.2).
	 *
	 * <p>그 키의 행이 없으면 0 이다. 행이 없는 것과 카운터가 0 이고 잠기지 않은 것은 결과가 같다
	 * (정본 §2.5) — 호출자가 0 을 실패로 다루지 않는다.
	 *
	 * <p>{@code updated_at} 은 앱 시계의 값을 <b>초로 자른 것</b>이다 (sp-docs/domain-model.md §1.1).
	 *
	 * <p><b>부르면 영속성 컨텍스트가 flush 되고 비워진다</b>({@link #resetAt} 의 설정). 앞서 읽은 엔터티는 다시
	 * 읽은 뒤 바꾼다 — 그대로 바꾸면 저장되지 않는다.
	 *
	 * @param emailKey {@link LoginAttempt#emailKeyOf(String)} 로 만든 키
	 * @return 갱신한 행 수
	 */
	default int reset(String emailKey, Clock clock) {
		return resetAt(emailKey, LocalDateTime.now(clock).truncatedTo(ChronoUnit.SECONDS));
	}

	/**
	 * {@link #reset} 의 문장이다. <b>{@link #reset} 으로 부른다</b> — {@code now} 를 초로 자르는 것은
	 * 그쪽이 한다. 자르지 않은 값을 넘기면 MySQL 은 소수부를 반올림하고 H2 는 남겨 두 DB 의
	 * {@code updated_at} 저장값이 갈린다 (sp-docs/domain-model.md §1.1).
	 *
	 * <p><b>이 문장은 영속성 컨텍스트를 flush 하고 비운다.</b> 앞서 읽은 엔터티는 준영속이 되어 그 뒤의
	 * 변경이 저장되지 않는다 — 이 문장 뒤에 엔터티를 바꾸려면 다시 읽는다.
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			update LoginAttempt a
			   set a.failedCount = 0,
			       a.lockedUntil = null,
			       a.updatedAt = :now
			 where a.emailKey = :emailKey
			""")
	int resetAt(@Param("emailKey") String emailKey, @Param("now") LocalDateTime now);

	/**
	 * 실패를 하나 센다. sp-docs/domain-model.md §2.5 「실패를 센다」 의 1) 이다 — 그 키의 행이 잠기지 않았을 때만 바꾸고,
	 * 마지막 실패({@code updated_at})가 {@code windowStart} 이하이면 1부터 다시 센다. 바꾼 행은 이 트랜잭션이 끝날 때까지
	 * 잠긴다 — {@link #lockIfReached} 의 판정이 그 행 락 아래에서 돈다.
	 *
	 * <p><b>SET 의 순서를 바꾸지 않는다.</b> MySQL 은 한 테이블 UPDATE 의 대입을 대개 왼쪽부터 하고, 뒤의 식은 앞에서 바뀐
	 * 값을 읽는다(MySQL 8.0 Reference Manual 의 UPDATE 문). {@code updated_at} 을 먼저 바꾸면 {@code CASE} 가 새 시각을
	 * 읽어 24시간이 지난 실패도 이어서 센다. H2 에서는 순서를 바꿔도 24시간 경계의 결과가 같다(AU-18 실측) — 그래서
	 * {@code LoginAttemptRepositoryTest} 가 문장의 순서를 SQL 로 본다.
	 *
	 * <p>부르면 영속성 컨텍스트가 flush 되고 비워진다({@link #resetAt} 과 같은 설정).
	 *
	 * @param emailKey {@link LoginAttempt#emailKeyOf(String)} 로 만든 키
	 * @param now 판정 시각. 앱 시계의 값을 초로 자른 것이다 (sp-docs/domain-model.md §2.5)
	 * @param windowStart {@code now} 에서 24시간 전. 마지막 실패가 이 시각 이하이면 1부터 센다
	 * @return 바꾼 행 수. 0 이면 행이 없거나 잠겨 있다 — 어느 쪽인지는 호출자가 행을 읽어 가른다
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			update LoginAttempt a
			   set a.failedCount = case when a.updatedAt <= :windowStart then 1 else a.failedCount + 1 end,
			       a.updatedAt = :now
			 where a.emailKey = :emailKey
			   and (a.lockedUntil is null or a.lockedUntil <= :now)
			""")
	int incrementFailure(@Param("emailKey") String emailKey, @Param("now") LocalDateTime now,
			@Param("windowStart") LocalDateTime windowStart);

	/**
	 * 센 실패가 한도에 이르렀으면 잠그고 카운터를 0 으로 한다. sp-docs/domain-model.md §2.5 「실패를 센다」 의 2) 다.
	 * {@link #incrementFailure} 가 1행을 바꾼 같은 트랜잭션에서 그 뒤에 부른다 — 증가가 잡은 행 락 아래에서 판정해야 같은
	 * 키의 동시 실패 중 정확히 하나가 잠근다 (sp-docs/requirements/member.md §12.2).
	 *
	 * <p>부르면 영속성 컨텍스트가 flush 되고 비워진다({@link #resetAt} 과 같은 설정).
	 *
	 * @param emailKey {@link LoginAttempt#emailKeyOf(String)} 로 만든 키
	 * @param threshold 잠그는 연속 실패 수
	 * @param now 판정 시각. 앱 시계의 값을 초로 자른 것이다
	 * @param lockedUntil 잠금이 풀리는 시각
	 * @return 1 이면 이번 실패가 잠갔다. 0 이면 한도 전이다
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			update LoginAttempt a
			   set a.lockedUntil = :lockedUntil,
			       a.failedCount = 0,
			       a.updatedAt = :now
			 where a.emailKey = :emailKey
			   and a.failedCount >= :threshold
			""")
	int lockIfReached(@Param("emailKey") String emailKey, @Param("threshold") int threshold,
			@Param("now") LocalDateTime now, @Param("lockedUntil") LocalDateTime lockedUntil);

}
