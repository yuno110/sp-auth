package com.example.auth.account.service;

import com.example.auth.account.dto.AccountCreateRequest;
import com.example.auth.account.dto.AccountResponse;
import com.example.auth.account.dto.CheckResponse;
import com.example.auth.account.entity.Account;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 계정 유스케이스. 정본: sp-docs/requirements/member.md §1 §2 §4,
 * sp-docs/api-contract.md §2.2 §9.1.
 *
 * <p>AU-05 가 만들고 AU-08·AU-09·AU-10 이 확장한다 (sp-docs/plan/phase1.md §2.3).
 *
 * <p><b>닉네임을 다루지 않는다.</b> 계정은 이메일·비밀번호·권한만 갖는다
 * (sp-docs/adr/0012-auth-as-separate-service.md).
 */
@Service
@RequiredArgsConstructor
public class AccountService {

	private final AccountRepository accountRepository;

	/** BCrypt strength 10. 빈은 AU-04 의 {@code SecurityConfig} 가 만든다 (sp-docs/security.md §1). */
	private final PasswordEncoder passwordEncoder;

	/**
	 * 가입 1단계 — 계정 생성 (sp-docs/requirements/member.md §4).
	 *
	 * <p>이메일이 이미 쓰이고 있으면 {@code AU002}(409)다. <b>탈퇴한 계정도 여기에 걸린다</b> —
	 * {@code deleted = true} 인 행이 남아 있고 {@code existsByEmail} 이 탈퇴 여부를 보지 않으므로
	 * 재가입이 막힌다 (sp-docs/requirements/member.md §3 규칙 1).
	 */
	@Transactional
	public AccountResponse create(AccountCreateRequest request) {
		if (this.accountRepository.existsByEmail(request.email())) {
			throw new BusinessException(ErrorCode.EMAIL_DUPLICATED);
		}

		Account account = Account.builder()
				.email(request.email())
				// 평문을 저장하지 않는다. 해싱은 서비스 계층의 몫이다
				.password(this.passwordEncoder.encode(request.password()))
				// role 은 지정하지 않는다 — 기본값 USER 다 (sp-docs/domain-model.md §2.1)
				.build();

		try {
			// saveAndFlush 다. save 만 하면 제약 위반이 커밋 시점(이 메서드 밖)에 터져
			// DataIntegrityViolationException 이 500 C005 로 새어 나간다
			return AccountResponse.from(this.accountRepository.saveAndFlush(account));
		} catch (DataIntegrityViolationException e) {
			// 위 검사와 INSERT 사이에 다른 요청이 같은 이메일을 선점한 경우다.
			// uk_account_email 이 최종 방어선이고, 사용자에게는 중복과 같은 상황이므로 AU002 다
			throw new BusinessException(ErrorCode.EMAIL_DUPLICATED);
		}
	}

	/**
	 * MR-02 — 이메일 중복 확인 (sp-docs/api-contract.md §2.3).
	 *
	 * <p><b>쓸 수 있으면 {@code true}</b>다. {@code existsByEmail} 이 탈퇴 여부를 보지 않으므로
	 * 탈퇴한 계정의 이메일은 {@code false} 가 된다.
	 *
	 * <p>이 확인은 경합을 막지 못한다 — 확인과 생성 사이에 다른 사용자가 같은 이메일을 쓸 수
	 * 있다. 최종 판정은 {@link #create} 의 {@code uk_account_email} 이다 (§2.3).
	 */
	@Transactional(readOnly = true)
	public CheckResponse checkEmail(String email) {
		return new CheckResponse(!this.accountRepository.existsByEmail(email));
	}

}
