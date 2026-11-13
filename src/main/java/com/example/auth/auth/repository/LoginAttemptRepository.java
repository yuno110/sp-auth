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

}
