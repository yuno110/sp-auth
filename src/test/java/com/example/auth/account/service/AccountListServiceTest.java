package com.example.auth.account.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.example.auth.account.dto.AccountSearchCondition;
import com.example.auth.account.dto.AccountSummaryResponse;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.account.repository.AccountQueryRepository;
import com.example.auth.auth.service.LoginAttemptService;
import com.example.auth.global.common.PageResponse;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.global.security.LoginAccount;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;

/**
 * AU-20 — 계정 목록의 ADMIN 판정과 {@code locked} 의 연결. 정본: sp-docs/security.md §5.1, sp-docs/api-contract.md §2.5.
 *
 * <p>목록 경로가 쓰는 협력자 둘만 스텁으로 두고 나머지는 {@code null} 로 넘긴다 — 목록 경로가 그것들을 부르면 NPE 로 드러난다.
 * HTTP 경로 전체는 {@code AccountListControllerTest} 가 본다.
 */
class AccountListServiceTest {

	private static final AccountSearchCondition CONDITION =
			AccountSearchCondition.of(null, null, null, null, null, null);

	private final AccountQueryRepository queryRepository = mock(AccountQueryRepository.class);

	private final LoginAttemptService loginAttemptService = mock(LoginAttemptService.class);

	private final PlatformTransactionManager transactionManager = mock(PlatformTransactionManager.class);

	private final AccountService service = new AccountService(
			null, null, null, null, null, null, null, null, this.queryRepository, this.loginAttemptService,
			this.transactionManager);

	@Test
	@DisplayName("USER 는 403 A004 이고 조회하지 않는다")
	void 사용자_거부() {
		assertThatThrownBy(() -> this.service.getList(new LoginAccount(2L, Role.USER), CONDITION))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.ACCESS_DENIED);
		verifyNoInteractions(this.queryRepository, this.loginAttemptService);
	}

	/**
	 * 「{@code ADMIN} 과 같을 때만 허용」 의 모양을 잠근다 (sp-docs/security.md §5.1). {@code Role} 에 값이 둘뿐이라 USER 만으로는
	 * 「USER 이면 거부」 와 구별되지 않는다 — 역할이 없는 주체가 허용 분기로 가지 않는지 본다.
	 */
	@Test
	@DisplayName("ADMIN 이 아닌 값(역할 없음)도 403 A004 다 — USER 만 거부하는 모양이 아니다")
	void 역할_없음_거부() {
		assertThatThrownBy(() -> this.service.getList(new LoginAccount(2L, null), CONDITION))
				.isInstanceOf(BusinessException.class)
				.extracting(e -> ((BusinessException) e).getErrorCode())
				.isEqualTo(ErrorCode.ACCESS_DENIED);
		verifyNoInteractions(this.queryRepository, this.loginAttemptService);
	}

	@Test
	@DisplayName("ADMIN 은 목록을 받고, locked 는 그 계정 이메일로 잠금 판정을 부른 값이다")
	void 관리자_허용() {
		Account locked = Account.builder().email("Locked@x.test").password("p").role(Role.USER).build();
		Account free = Account.builder().email("free@x.test").password("p").role(Role.USER).build();
		given(this.queryRepository.search(any()))
				.willReturn(new PageImpl<>(List.of(locked, free), PageRequest.of(0, 20), 2));
		given(this.loginAttemptService.isLocked("Locked@x.test")).willReturn(true);
		given(this.loginAttemptService.isLocked("free@x.test")).willReturn(false);

		PageResponse<AccountSummaryResponse> page =
				this.service.getList(new LoginAccount(1L, Role.ADMIN), CONDITION);

		assertThat(page.content())
				.extracting(AccountSummaryResponse::email, AccountSummaryResponse::locked)
				.containsExactly(tuple("Locked@x.test", true), tuple("free@x.test", false));
		assertThat(page.size()).isEqualTo(20);
		assertThat(page.totalElements()).isEqualTo(2);

		// 목록과 개수는 읽기 전용 트랜잭션 하나 안에서 읽고, 잠금 판정은 그 트랜잭션이 끝난 뒤에 부른다 (conventions.md §5)
		InOrder order = inOrder(this.transactionManager, this.queryRepository, this.loginAttemptService);
		order.verify(this.transactionManager).getTransaction(argThat(TransactionDefinition::isReadOnly));
		order.verify(this.queryRepository).search(CONDITION);
		order.verify(this.transactionManager).commit(any());
		order.verify(this.loginAttemptService).isLocked("Locked@x.test");
	}

}
