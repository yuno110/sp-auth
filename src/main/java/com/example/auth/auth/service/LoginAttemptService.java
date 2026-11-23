package com.example.auth.auth.service;

import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.auth.repository.LoginAttemptRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.NestedExceptionUtils;
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
 * {@link TransactionTemplate} 으로 연다 — {@link #countFailure} 의 catch 가 트랜잭션 경계 밖에 있어야, 락 경합 때 세기의
 * 트랜잭션을 되돌린 뒤 {@code AU003} 을 낸다. 애노테이션이면 catch 가 경계 안이라, 예외를 삼킨 뒤 프록시가 그 트랜잭션을
 * 커밋하려 한다.
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
	 * <p>순서는 sp-docs/domain-model.md §2.5 「실패를 센다」 다 — 새 트랜잭션 하나에서 1) 한 문장 upsert
	 * ({@link LoginAttemptRepository#countFailure})로 세고 한도에 닿으면 잠근 뒤, 2) 같은 트랜잭션에서 그 키의 행을 읽어
	 * {@code locked_until > now} 이면 {@code true} 다. 한도 판정은 그 문장 안에 있고 문장이 그 행의 락을 쥐므로 같은 키의
	 * 동시 실패가 한 줄로 서 정확히 하나가 잠근다. 2) 는 1) 이 쥔 행 락 아래이고 그 트랜잭션의 첫 일관 읽기라 1) 앞에
	 * 커밋된 잠금도 본다(정본 §2.5). 1) 앞에 같은 트랜잭션에서 그 행을 읽지 않는다. <b>1) 의 영향 행 수로 판정하지
	 * 않는다</b> — 그 값은 DB 와 드라이버 설정에 따라 다를 수 있다(정본 §2.5). 1) 뒤에 행이 없으면 삼키지 않고 던진다.
	 *
	 * <p><b>다시 하는 자리가 없다</b>(2026-11-23 sp-docs D-27). 1) 은 그 키의 UNIQUE 충돌을 갱신으로 바꾸므로 같은 키의 동시
	 * 첫 실패가 UNIQUE 충돌을 내지 않는다. 그래도 제약 위반이 나면 락 경합이 아닌 DB 실패로 던진다 — 잡아서 다시 하거나
	 * {@code AU003} 으로 삼키지 않는다. 키가 비지 않고 100자 이하인 것은 부르는 쪽이 먼저 검사한다
	 * (sp-docs/requirements/member.md §12.1 의 1).
	 *
	 * <p><b>락 경합</b>으로 실패하면 다시 하지 않고 {@code false} 를 돌려주며 세지 못한 실패를 WARN 한 줄로 남긴다 — 락 경합은
	 * 스프링이 비관적 락 실패({@link PessimisticLockingFailureException})로 옮긴 예외다(예: MySQL 의 교착 1213, 잠금 대기 시간
	 * 초과 1205). 정본 §2.5 의 「락 경합은 다시 하지 않는다」 다. 1) 로 새 키를 넣은 트랜잭션이 되돌아가면 그 키를 기다리던
	 * 시도끼리 교착할 수 있다(정본 §2.5 의 「남는 교착」) — 그것도 이 갈래다. WARN 줄에는 이메일·키를 싣지 않는다.
	 *
	 * <p><b>락 경합이 아닌 DB 실패는 삼키지 않고 던진다</b> — 연결을 얻지 못한 것도, 제약 위반도 그렇다. 마지막 그물이 500
	 * {@code C005} 로 받는다(sp-docs/conventions.md §6.1). {@code AU003} 으로 삼키면 DB 가 실패하는 동안의 실패가 세지지 않은
	 * 채 보통의 실패 응답으로 나간다 — 잠금이 열리는 쪽으로 실패한다.
	 */
	public boolean countFailure(String email) {
		String key = LoginAttempt.emailKeyOf(email);
		LocalDateTime now = now();
		try {
			return Boolean.TRUE.equals(this.newTransaction.execute(status -> count(key, now)));
		} catch (PessimisticLockingFailureException e) {
			// 예외 객체를 로그 인자로 넘기지 않는다 — 넘기면 메시지와 스택이 함께 남고, DB 가 낸 메시지에는 키가 실릴 수 있다
			log.warn("login failure not counted: exception={}, cause={}", e.getClass().getName(),
					NestedExceptionUtils.getMostSpecificCause(e).getClass().getName());
			return false;
		}
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
	 * sp-docs/domain-model.md §2.5 「실패를 센다」 의 1)·2). 세기의 트랜잭션 안에서 부른다. 이번 실패가 잠갔거나 그 사이
	 * 다른 시도가 잠갔으면 {@code true}.
	 */
	private boolean count(String key, LocalDateTime now) {
		this.loginAttemptRepository.countFailure(key, now, now.minus(FAILURE_WINDOW), LOCK_THRESHOLD,
				now.plus(LOCK_DURATION));
		// 문장이 영속성 컨텍스트를 비웠으므로 DB 에서 읽는다. 새로 연 이 트랜잭션에서 읽는다 — 부른 쪽 트랜잭션의 스냅샷이 아니다
		LoginAttempt row = this.loginAttemptRepository.findByEmailKey(key)
				.orElseThrow(() -> new IllegalStateException("login_attempt row missing after counting a failure"));
		return lockedAt(row, now);
	}

	private static boolean lockedAt(LoginAttempt attempt, LocalDateTime now) {
		return attempt.getLockedUntil() != null && attempt.getLockedUntil().isAfter(now);
	}

	private LocalDateTime now() {
		return LocalDateTime.now(this.clock).truncatedTo(ChronoUnit.SECONDS);
	}

}
