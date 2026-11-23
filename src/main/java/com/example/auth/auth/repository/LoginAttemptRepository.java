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
	 * 실패를 하나 센다. sp-docs/domain-model.md §2.5 「실패를 센다」 의 1) 이다 — 그 키의 행이 없으면
	 * {@code (:key, 1, NULL, :now)} 를 넣고, 있으면 UNIQUE({@code uk_login_attempt_email_key}) 충돌을 갱신으로 바꿔 한 문장
	 * 안에서 세고 한도에 닿으면 잠근다. 문장은 그 키의 행 락을 쥐므로 같은 키의 동시 실패가 한 줄로 선다. 바뀐 행은 이
	 * 트랜잭션이 끝날 때까지 잠긴다 — 판정은 같은 트랜잭션에서 이 문장 뒤에 그 행을 읽어 한다({@link #findByEmailKey}).
	 *
	 * <p>문장의 뜻(정본 「1) 의 뜻」): 잠긴 행({@code locked_until > :now})은 값이 바뀌지 않는다 — 식은 {@code failed_count} 에
	 * 0 을, 같은 초에 잠긴 행이면 {@code updated_at} 에 {@code :now} 를 쓰지만 잠그는 문장이 만든 행은 이미 그 값이다.
	 * 잠기지 않은 행은 마지막 실패가 {@code windowStart} 이하이면 1부터, 아니면 이어서 세고, 그 수가 {@code threshold} 에
	 * 이르면 {@code locked_until = lockedUntil}, {@code failed_count = 0} 이다. 어느 쪽이든 {@code updated_at = :now} 다.
	 *
	 * <p><b>문장을 정본과 식까지 같게 둔다</b> — 2026-11-23 실 MySQL 과 H2 에서 잰 모양이다(정본 §2.5, sp-docs D-27). 바꾸면
	 * 두 DB 에서 다시 잰다. 정본의 {@code :now - 24h}·{@code :now + 15m}·{@code 5} 를 인자
	 * {@code windowStart}·{@code lockedUntil}·{@code threshold} 로 받는다 — 값을 고르는 것은 카운터 빈이다.
	 * <ul>
	 *   <li><b>SET 의 순서를 바꾸지 않는다 — {@code locked_until}, {@code failed_count}, {@code updated_at} 이다.</b> MySQL
	 *   은 대입을 왼쪽부터 하고 뒤의 식이 앞에서 바뀐 값을 읽는다(MySQL 8.0 Reference Manual 의 UPDATE 문). H2(MySQL
	 *   모드)는 모든 SET 식이 옛 값을 읽는다. 이 순서에서 두 읽기가 같은 결과를 낸다. 순서를 바꾸면 MySQL 에서 뜻이
	 *   바뀌고(예: {@code updated_at} 을 앞에 두면 창 판정이 바뀐 시각을 읽는다) H2 의 결과는 그대로라 결과를 보는 테스트가
	 *   잡지 못한다 — {@code LoginAttemptRepositoryTest} 가 Hibernate 가 준비한 SQL 을 정본과 대조한다.
	 *   이번 시도가 잠그면 {@code failed_count} 식은 MySQL 에서 첫 줄(바뀐 {@code locked_until}), H2 에서 셋째 줄
	 *   ({@code failed_count + 1 >= threshold THEN 0})로 가서 둘 다 0 이다 — 셋째 줄을 빼면 H2 에서 5 인 채 잠긴다</li>
	 *   <li><b>{@code updated_at} 식의 조건 {@code locked_until <> lockedUntil} 을 빼지 않는다.</b> MySQL 에서는 이 식도
	 *   이번에 바뀐 {@code locked_until} 을 읽으므로 이 절이 이번 시도가 막 잠근 행({@code :now} 를 쓴다)과 이미 잠긴
	 *   행(그대로)을 가른다. 빼면 MySQL 에서만 막 잠근 행이 옛 {@code updated_at} 을 지녀, 정리 작업이 잠금 중인 행을
	 *   일찍 지울 수 있다. H2 는 옛 값을 읽어 결과가 같다 — 이것도 SQL 대조만 본다.
	 *   {@code OR updated_at = :now} 는 값으로는 군더더기지만 잰 문장과 같게 둔다</li>
	 * </ul>
	 *
	 * <p><b>영향 행 수를 돌려주지 않는다</b> — 판정은 이 문장 뒤의 행 읽기로 한다(정본 §2.5). 그 값은 DB 와 드라이버의
	 * 설정({@code CLIENT_FOUND_ROWS})에 따라 다를 수 있고 앱이 쓰는 Connector/J 의 값은 재지 않았다.
	 *
	 * <p>트랜잭션 안에서 부른다. 부르면 영속성 컨텍스트가 flush 되고 비워진다({@link #resetAt} 과 같은 설정) — 뒤의 행
	 * 읽기가 DB 에서 읽는다.
	 *
	 * @param emailKey {@link LoginAttempt#emailKeyOf(String)} 로 만든 키
	 * @param now 판정 시각. 앱 시계의 값을 초로 자른 것이다 (sp-docs/domain-model.md §2.5)
	 * @param windowStart {@code now} 에서 24시간 전. 마지막 실패가 이 시각 이하이면 1부터 센다
	 * @param threshold 잠그는 연속 실패 수
	 * @param lockedUntil 이번 시도가 잠그면 쓰는 잠금이 풀리는 시각({@code now} 에서 15분 뒤)
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query(nativeQuery = true, value = """
			INSERT INTO login_attempt (email_key, failed_count, locked_until, updated_at)
			VALUES (:emailKey, 1, NULL, :now)
			ON DUPLICATE KEY UPDATE
			  locked_until = CASE WHEN locked_until > :now THEN locked_until
			                      WHEN (CASE WHEN updated_at <= :windowStart THEN 1 ELSE failed_count + 1 END) >= :threshold
			                           THEN :lockedUntil
			                      ELSE locked_until END,
			  failed_count = CASE WHEN locked_until > :now THEN 0
			                      WHEN updated_at <= :windowStart THEN 1
			                      WHEN failed_count + 1 >= :threshold THEN 0
			                      ELSE failed_count + 1 END,
			  updated_at   = CASE WHEN locked_until > :now
			                           AND (locked_until <> :lockedUntil OR updated_at = :now) THEN updated_at
			                      ELSE :now END
			""")
	void countFailure(@Param("emailKey") String emailKey, @Param("now") LocalDateTime now,
			@Param("windowStart") LocalDateTime windowStart, @Param("threshold") int threshold,
			@Param("lockedUntil") LocalDateTime lockedUntil);

	/**
	 * 마지막으로 바뀐 시각이 {@code cutoff} 보다 이른 행을 지운다 — 정리 작업의 문장이다 (sp-docs/domain-model.md §2.5).
	 *
	 * <p>{@code cutoff} 는 판정 시각에서 24시간 전이다. 그보다 이른 행은 {@link #countFailure} 의 {@code CASE} 가
	 * 1부터 다시 세는 행({@code updated_at <= windowStart})이고, 잠금(15분)도 이미 풀렸다 — 지운 행과 결과가 같다. 경계에
	 * 놓인 행({@code updated_at = cutoff})은 남긴다. 그 행도 1부터 다시 세지만 「이른」 행이 아니다.
	 *
	 * <p>트랜잭션 안에서 부른다.
	 *
	 * @return 지운 행 수
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			delete from LoginAttempt a
			 where a.updatedAt < :cutoff
			""")
	int deleteUpdatedBefore(@Param("cutoff") LocalDateTime cutoff);

}
