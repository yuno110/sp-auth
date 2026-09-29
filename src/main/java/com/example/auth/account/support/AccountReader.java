package com.example.auth.account.support;

import com.example.auth.account.entity.Account;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * 계정 조회의 "없으면 예외" 지점을 한곳에 둔다.
 *
 * <p>{@code AU001}(404, 계정을 찾을 수 없습니다) 은 sp-docs/api-contract.md §8.4 가 정본이다.
 *
 * <p><b>탈퇴 여부는 보지 않는다.</b> 탈퇴한 계정도 행은 존재하므로 조회는 성공한다.
 * {@code deleted} 검사는 기능별로 다르다 — 로그인·재발급은 거부하고(§3 규칙 5), 계정 탈퇴는
 * 이미 탈퇴한 계정에도 204 를 돌려주는 멱등 연산이다(sp-docs/api-contract.md §2.2).
 * 여기서 일괄 거부하면 그 차이가 사라진다.
 */
@Component
@RequiredArgsConstructor
public class AccountReader {

	private final AccountRepository accountRepository;

	public Account getById(Long id) {
		return accountRepository.findById(id)
				.orElseThrow(() -> new BusinessException(ErrorCode.ACCOUNT_NOT_FOUND));
	}

}
