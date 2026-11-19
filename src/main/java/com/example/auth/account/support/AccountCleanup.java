package com.example.auth.account.support;

import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.auth.repository.LoginAttemptRepository;
import com.example.auth.auth.service.LoginAttemptService;
import java.time.Clock;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 만료된 {@code account_token} 과 오래된 {@code login_attempt} 의 정리 작업. 정본: sp-docs/domain-model.md §2.4·§2.5,
 * sp-docs/tech-stack.md §4.7.
 *
 * <p><b>지워도 판정 결과가 바뀌지 않는 행만 지운다.</b> 토큰은 만료된 행({@code expires_at <= now}) — 확인의 사용 처리가
 * 이미 0행으로 보는 행이라 지운 토큰과 만료된 토큰의 확인이 둘 다 {@code AU007} 이다. 잠금 행은 마지막으로 바뀐 시각이
 * 24시간({@link LoginAttemptService#FAILURE_WINDOW})보다 이른 행 — 잠금(15분)은 이미 풀렸고 다음 실패가 1부터 다시 세어지므로
 * 행이 없을 때의 첫 실패(1)와 같다.
 *
 * <p><b>판정 시각은 주입한 {@link Clock} 의 값을 초로 자른 것이다</b> — 확인과 실패 세기가 쓰는 앱 시계와 같다. DB 의
 * {@code NOW()} 를 쓰지 않는다.
 *
 * <p><b>실행 위치를 고르지 않는다</b> (sp-docs/tech-stack.md §4.7). 인스턴스마다 각자 돈다 — 두 삭제는 조건만으로 대상을
 * 정하는 벌크 DELETE 라, 여럿이 같은 때 돌아도 지워지는 행의 합이 같고 남는 행이 같다.
 *
 * <p><b>주기는 {@code account-cleanup.interval} 이다</b>(편의값) — 앞 실행이 끝난 뒤부터 잰다. <b>첫 실행도 기동 뒤 그
 * 주기만큼 늦춘다.</b> 기동 직후에 돌면 그 실행이 다른 스레드에서 테스트가 바꿔 끼운 시계를 읽어, 시계를 앞으로 움직인
 * 테스트의 행을 그 테스트 도중에 지울 수 있다. 판정에는 영향이 없다(정본 §4.7) — 정리가 늦어지는 만큼 행이 더 머물 뿐이다.
 *
 * <p><b>실패를 삼키지 않는다.</b> 잡지 않은 예외는 스케줄러의 오류 처리기가 로그로 남기고 다음 주기가 돈다. 정리가 멈추면
 * 행이 쌓인다(sp-docs/nfr.md §4).
 */
@Component
public class AccountCleanup {

	private final AccountTokenRepository accountTokenRepository;

	private final LoginAttemptRepository loginAttemptRepository;

	/** 삭제마다 여는 트랜잭션. 벌크 DELETE 는 부르는 쪽의 트랜잭션이 필요하다. */
	private final TransactionTemplate cleanupTransaction;

	private final Clock clock;

	public AccountCleanup(
			AccountTokenRepository accountTokenRepository,
			LoginAttemptRepository loginAttemptRepository,
			PlatformTransactionManager transactionManager,
			Clock clock) {

		this.accountTokenRepository = accountTokenRepository;
		this.loginAttemptRepository = loginAttemptRepository;
		this.cleanupTransaction = new TransactionTemplate(transactionManager);
		this.clock = clock;
	}

	/**
	 * 지금(앱 시계)을 기준으로 두 테이블을 정리한다. 두 삭제는 서로 다른 테이블이라 각자의 트랜잭션에서 한다 — 한쪽이
	 * 실패해도 이미 커밋된 다른 쪽을 되돌릴 이유가 없다. <b>한쪽이 실패해도 다른 쪽은 돈다</b> — 토큰 삭제가 주기마다
	 * 실패해도 잠금 행의 정리까지 멈추지 않게 한다. 실패는 삼키지 않고 다른 쪽을 돈 뒤 다시 던진다(둘 다 실패하면 뒤의 것을
	 * 앞의 것에 덧붙인다).
	 */
	@Scheduled(fixedDelayString = "${account-cleanup.interval}", initialDelayString = "${account-cleanup.interval}")
	public void run() {
		LocalDateTime now = LocalDateTime.now(this.clock).truncatedTo(ChronoUnit.SECONDS);
		RuntimeException failure = null;
		try {
			this.cleanupTransaction.executeWithoutResult(
					status -> this.accountTokenRepository.deleteExpiredAt(now));
		}
		catch (RuntimeException ex) {
			failure = ex;
		}
		try {
			this.cleanupTransaction.executeWithoutResult(
					status -> this.loginAttemptRepository.deleteUpdatedBefore(now.minus(LoginAttemptService.FAILURE_WINDOW)));
		}
		catch (RuntimeException ex) {
			if (failure == null) {
				throw ex;
			}
			failure.addSuppressed(ex);
		}
		if (failure != null) {
			throw failure;
		}
	}

}
