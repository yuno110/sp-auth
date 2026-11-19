package com.example.auth.account.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.auth.repository.LoginAttemptRepository;
import java.time.Clock;
import java.time.LocalDateTime;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * 정리 작업의 두 삭제가 서로의 실패에 묶이지 않는지 본다 — 한쪽이 주기마다 실패해도 다른 쪽 정리가 멈추지 않고, 실패는
 * 삼키지 않는다 ({@link AccountCleanup#run()}).
 */
class AccountCleanupFailureTest {

	private final AccountTokenRepository tokens = mock(AccountTokenRepository.class);

	private final LoginAttemptRepository attempts = mock(LoginAttemptRepository.class);

	private final AccountCleanup cleanup = new AccountCleanup(this.tokens, this.attempts,
			mock(PlatformTransactionManager.class), Clock.systemDefaultZone());

	@Test
	@DisplayName("토큰 삭제가 실패해도 잠금 행은 지우고, 토큰의 실패를 던진다")
	void 토큰_삭제가_실패해도_잠금_행은_지운다() {
		IllegalStateException tokenFailure = new IllegalStateException("토큰");
		given(this.tokens.deleteExpiredAt(any(LocalDateTime.class))).willThrow(tokenFailure);

		assertThatThrownBy(this.cleanup::run).isSameAs(tokenFailure);
		verify(this.attempts).deleteUpdatedBefore(any(LocalDateTime.class));
	}

	@Test
	@DisplayName("잠금 행 삭제만 실패하면 토큰은 지우고, 그 실패를 던진다")
	void 잠금_행_삭제만_실패하면_그_실패를_던진다() {
		IllegalStateException attemptFailure = new IllegalStateException("잠금 행");
		given(this.attempts.deleteUpdatedBefore(any(LocalDateTime.class))).willThrow(attemptFailure);

		assertThatThrownBy(this.cleanup::run).isSameAs(attemptFailure);
		verify(this.tokens).deleteExpiredAt(any(LocalDateTime.class));
	}

	@Test
	@DisplayName("둘 다 실패하면 앞의 실패에 뒤의 실패를 덧붙여 던진다")
	void 둘_다_실패하면_덧붙인다() {
		IllegalStateException tokenFailure = new IllegalStateException("토큰");
		IllegalStateException attemptFailure = new IllegalStateException("잠금 행");
		given(this.tokens.deleteExpiredAt(any(LocalDateTime.class))).willThrow(tokenFailure);
		given(this.attempts.deleteUpdatedBefore(any(LocalDateTime.class))).willThrow(attemptFailure);

		assertThatThrownBy(this.cleanup::run).isSameAs(tokenFailure)
			.satisfies(ex -> assertThat(ex.getSuppressed()).containsExactly(attemptFailure));
	}

}
