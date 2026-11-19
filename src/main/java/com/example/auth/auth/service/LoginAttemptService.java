package com.example.auth.auth.service;

import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.auth.repository.LoginAttemptRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 로그인 잠금의 카운터 (sp-docs/requirements/member.md §12). 갱신 문장은 sp-docs/domain-model.md §2.5 다.
 *
 * <p><b>모든 일을 부른 쪽과 다른 새 트랜잭션에서 하고 곧바로 커밋한다</b>({@code PROPAGATION_REQUIRES_NEW}). 로그인의
 * {@code AU003}·{@code AU005}·{@code AU006} 응답은 예외다 — 세기나 0 으로 하기가 그 예외로 되돌려지는 트랜잭션 안에서 돌면 함께
 * 되돌려진다 (sp-docs/requirements/member.md §12.2). 그래서 부른 쪽에 트랜잭션이 있어도 그것과 따로 연다. 그때는 부른 쪽
 * 트랜잭션을 멈춘 채 연결을 하나 더 얻는다 — 부른 쪽이 연결을 쥔 채 이 빈을 부르면 한 요청이 연결 둘을 쥔다. 그 비용과
 * 실측은 {@link AuthService#login} 에 있다.
 *
 * <p><b>로그인 서비스와 다른 빈이다</b> (sp-docs/conventions.md §1.1). 트랜잭션은 애노테이션이 아니라
 * {@link TransactionTemplate} 으로 연다 — 다시 하기가 이 빈 안에서 새 트랜잭션을 한 번 더 열어야 하는데, 같은 빈 안의
 * 호출은 프록시를 지나지 않아 애노테이션의 전파 설정이 먹지 않는다.
 *
 * <p>키는 로그인 요청의 이메일을 {@link LoginAttempt#emailKeyOf(String)} 로 바꾼 값이다. 판정 시각은 주입한 {@link Clock}
 * 의 값을 초로 자른 것이다 (sp-docs/domain-model.md §2.5).
 */
@Service
public class LoginAttemptService {

	/** 연속 실패가 이 수에 이르면 잠근다 (sp-docs/requirements/member.md §12). */
	private static final int LOCK_THRESHOLD = 5;

	/** 잠금의 길이 (sp-docs/requirements/member.md §12.1). */
	private static final Duration LOCK_DURATION = Duration.ofMinutes(15);

	/**
	 * 마지막 실패에서 이만큼 지난 실패는 1부터 다시 센다 (sp-docs/requirements/member.md §12.2). 오래된 행의 정리
	 * ({@code AccountCleanup})가 같은 창을 쓴다 — 이 창보다 이른 행만 지워 지운 행과 남은 행의 다음 실패가 같게 한다
	 * (sp-docs/domain-model.md §2.5).
	 */
	public static final Duration FAILURE_WINDOW = Duration.ofHours(24);

	private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

	private final LoginAttemptRepository loginAttemptRepository;

	/** 실패 세기와 0 으로 하기의 트랜잭션. 부른 쪽의 트랜잭션을 멈추고 새로 연다. */
	private final TransactionTemplate newTransaction;

	/** 잠금 판정의 트랜잭션. 부른 쪽의 트랜잭션을 멈추고 새로 열어 읽기만 한다. */
	private final TransactionTemplate newReadOnlyTransaction;

	private final Clock clock;

	public LoginAttemptService(
			LoginAttemptRepository loginAttemptRepository,
			PlatformTransactionManager transactionManager,
			Clock clock) {

		this.loginAttemptRepository = loginAttemptRepository;
		this.newTransaction = new TransactionTemplate(transactionManager);
		this.newTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.newReadOnlyTransaction = new TransactionTemplate(transactionManager);
		this.newReadOnlyTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		this.newReadOnlyTransaction.setReadOnly(true);
		this.clock = clock;
	}

	/**
	 * sp-docs/requirements/member.md §12.1 의 3 — 그 이메일이 지금 잠겨 있는가. {@code locked_until} 이 판정 시각보다
	 * 뒤이면 잠겼다.
	 *
	 * <p><b>최신 커밋 값을 읽는다</b> (sp-docs/requirements/member.md §12.2). 읽기 전용 새 트랜잭션의 첫 읽기로 읽는다 — MySQL
	 * 의 반복 읽기에서 스냅샷은 그 트랜잭션의 첫 일관 읽기 때 정해진다(MySQL 8.0 Reference Manual 의 Consistent Nonlocking
	 * Reads). 부른 쪽에 먼저 열린 트랜잭션이 있어도 그 스냅샷으로 읽지 않는다 — 그 스냅샷이 BCrypt 비교 전에 정해졌다면 비교 동안
	 * 커밋된 잠금을 보지 못한다.
	 *
	 * <p>부른 쪽 트랜잭션 안의 잠금 읽기({@code for update})로 읽지 않는다. 그 행 락은 부른 쪽 트랜잭션이 끝날 때 풀리는데, 같은
	 * 스레드가 그 트랜잭션을 멈춘 채 {@link #countFailure} 의 새 트랜잭션에서 그 행을 바꾸려 하면 스레드가 자기를 기다린다. DB
	 * 에게는 두 트랜잭션 중 하나가 다른 하나를 기다리는 것뿐이라 교착으로 보이지 않고, 락 대기 시간이 다할 때까지 멈춘다.
	 *
	 * <p>읽기가 실패하면 삼키지 않고 던진다 — 잠기지 않은 것으로 삼으면 잠금이 열린다.
	 */
	public boolean isLocked(String email) {
		String key = LoginAttempt.emailKeyOf(email);
		LocalDateTime now = now();
		return Boolean.TRUE.equals(this.newReadOnlyTransaction.execute(status -> this.loginAttemptRepository
				.findByEmailKey(key)
				.filter(attempt -> lockedAt(attempt, now))
				.isPresent()));
	}

	/**
	 * sp-docs/requirements/member.md §12.1 의 4 — 실패를 하나 센다. 이번 실패로 한도에 이르렀거나 그 사이 다른 시도가
	 * 잠갔으면 {@code true}(응답은 {@code AU005}), 아니면 {@code false}({@code AU003}).
	 *
	 * <p>순서는 sp-docs/domain-model.md §2.5 「실패를 센다」 다 — 조건부 UPDATE, 0행이면 그 키의 행을 읽어 가르고, 행이 없으면
	 * INSERT. 한도 판정은 증가와 같은 트랜잭션에서 증가가 잡은 행 락 아래에서 한다. 읽고 비교한 뒤 쓰지 않는다.
	 *
	 * <p><b>다시 하는 자리</b>는 정본 §2.5 의 「다시 하는 자리(UNIQUE 충돌, 잠기지 않은 행)는 새 트랜잭션이다」 다 — INSERT 의
	 * UNIQUE 충돌은 같은 키의 동시 첫 실패이고, 0행인데 잠기지 않은 행은 그 사이 다른 시도가 넣은 것이다. 새 트랜잭션에서
	 * 처음부터 한 번 더 한다 — 제약 위반이 그 트랜잭션을 rollback-only 로 만들 수 있다(정본 §2.5). 한 번 더 해도 세지 못하면
	 * {@code false} 이고 세지 못한 실패를 WARN 한 줄로 남긴다.
	 *
	 * <p><b>락 경합</b>으로 실패하면 다시 하지 않고 {@code false} 를 돌려주며 세지 못한 실패를 WARN 한 줄로 남긴다 — 락 경합은
	 * 스프링이 비관적 락 실패({@link PessimisticLockingFailureException})로 옮긴 예외다(예: 교착). 정본 §2.5 는 「한 번 더 해도
	 * 실패하면(예: 교착) 로그인 응답은 {@code AU003} 그대로이고 세지 못한 실패를 WARN 으로 남긴다」 고 적고, 같은 키의 동시 첫
	 * 실패가 간격 락으로 교착할 수 있다고 추정한다. WARN 줄에는 이메일·키를 싣지 않는다.
	 *
	 * <p><b>락 경합이 아닌 DB 실패는 삼키지 않고 던진다</b> — 연결을 얻지 못한 것도 그렇다. 마지막 그물이 500 {@code C005} 로
	 * 받는다(sp-docs/conventions.md §6.1). {@code AU003} 으로 삼키면 DB 가 실패하는 동안의 실패가 세지지 않은 채 보통의 실패
	 * 응답으로 나간다 — 잠금이 열리는 쪽으로 실패한다.
	 */
	public boolean countFailure(String email) {
		String key = LoginAttempt.emailKeyOf(email);
		LocalDateTime now = now();
		try {
			Count count = countInNewTransaction(key, now);
			if (count == Count.RETRY) {
				count = countInNewTransaction(key, now);
			}
			if (count != Count.RETRY) {
				return count == Count.LOCKED;
			}
			log.warn("login failure not counted: concurrent first failure on retry");
		} catch (PessimisticLockingFailureException e) {
			// 예외 객체를 로그 인자로 넘기지 않는다 — 넘기면 메시지와 스택이 함께 남고, DB 가 낸 메시지에는 키가 실릴 수 있다
			log.warn("login failure not counted: exception={}, cause={}", e.getClass().getName(),
					NestedExceptionUtils.getMostSpecificCause(e).getClass().getName());
		}
		return false;
	}

	/**
	 * sp-docs/requirements/member.md §12.1 의 5·6 — 비밀번호가 맞았다. 카운터를 0 으로 하고 잠금을 비운다
	 * ({@link LoginAttemptRepository#reset}). 그 키의 행이 없으면 바꾸는 것이 없다. DB 가 실패하면 삼키지 않고 던진다.
	 */
	public void reset(String email) {
		String key = LoginAttempt.emailKeyOf(email);
		this.newTransaction.executeWithoutResult(status -> this.loginAttemptRepository.reset(key, this.clock));
	}

	/**
	 * 한 번의 세기를 새 트랜잭션에서 한다. {@link Count#RETRY} 는 다시 하는 자리다.
	 *
	 * <p>{@link DataIntegrityViolationException} 은 그 트랜잭션이 되돌려진 뒤 여기서 받고, 같은 키의 동시 첫 실패로 읽는다 —
	 * 정본 §2.5 의 「UNIQUE 충돌이면 같은 키의 동시 첫 실패다」. 키가 비지 않고 100자 이하라는 것(sp-docs/requirements/member.md
	 * §12.1 의 1 — 부르는 쪽이 먼저 검사한다)이 그 전제다.
	 */
	private Count countInNewTransaction(String key, LocalDateTime now) {
		try {
			return this.newTransaction.execute(status -> count(key, now));
		} catch (DataIntegrityViolationException e) {
			return Count.RETRY;
		}
	}

	/** sp-docs/domain-model.md §2.5 「실패를 센다」 의 1)·2). 트랜잭션 안에서 부른다. */
	private Count count(String key, LocalDateTime now) {
		if (this.loginAttemptRepository.incrementFailure(key, now, now.minus(FAILURE_WINDOW)) == 1) {
			int locked = this.loginAttemptRepository.lockIfReached(key, LOCK_THRESHOLD, now, now.plus(LOCK_DURATION));
			return (locked == 1) ? Count.LOCKED : Count.COUNTED;
		}
		// 0행 — 행이 없거나 잠겼다. 읽어서 가른다. 새로 연 이 트랜잭션에서 읽는다 — 부른 쪽 트랜잭션의 스냅샷이 아니다
		Optional<LoginAttempt> row = this.loginAttemptRepository.findByEmailKey(key);
		if (row.isPresent()) {
			// 잠기지 않은 행이면 그 사이 다른 트랜잭션이 그 행을 넣었거나 풀었다 — 다시 센다. 잠긴 것으로 읽으면 거짓 잠금이
			// 나고 이번 실패가 사라진다
			return lockedAt(row.get(), now) ? Count.LOCKED : Count.RETRY;
		}
		// INSERT 도 판정 시각을 넣는다 — 정본 §2.5 의 (:key, 1, NULL, :now). 시계를 다시 읽으면 그 사이 초가 넘어갈 때
		// 24시간 경계가 판정 시각과 어긋난다
		this.loginAttemptRepository.saveAndFlush(LoginAttempt.firstFailure(key, stoppedAt(now)));
		return Count.COUNTED;
	}

	private static boolean lockedAt(LoginAttempt attempt, LocalDateTime now) {
		return attempt.getLockedUntil() != null && attempt.getLockedUntil().isAfter(now);
	}

	private LocalDateTime now() {
		return LocalDateTime.now(this.clock).truncatedTo(ChronoUnit.SECONDS);
	}

	/** 판정 시각에 멈춘 시계 — 시계를 받는 {@link LoginAttempt#firstFailure} 에 판정 시각을 건넨다. */
	private Clock stoppedAt(LocalDateTime now) {
		return Clock.fixed(now.atZone(this.clock.getZone()).toInstant(), this.clock.getZone());
	}

	/** 한 번의 세기의 결과. */
	private enum Count {

		/** 셌고 한도 전이다 — {@code AU003}. */
		COUNTED,

		/** 이번 실패가 잠갔거나 그 사이 다른 시도가 잠갔다 — {@code AU005}. */
		LOCKED,

		/** 다시 하는 자리다 — 새 트랜잭션에서 처음부터 한 번 더. */
		RETRY

	}

}
