package com.example.auth.account.service;

import com.example.auth.account.dto.AccountCreateRequest;
import com.example.auth.account.dto.AccountResponse;
import com.example.auth.account.dto.CheckResponse;
import com.example.auth.account.dto.PasswordChangeRequest;
import com.example.auth.account.entity.Account;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.support.AccountReader;
import com.example.auth.auth.repository.RefreshTokenRepository;
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

	/** "없으면 {@code AU001}" 을 한곳에 둔다. 빈은 AU-04 가 선제 준비했다. */
	private final AccountReader accountReader;

	/**
	 * 비밀번호 변경이 Refresh Token 을 지운다 (sp-docs/requirements/member.md §3 규칙 4).
	 *
	 * <p><b>{@code account} 가 {@code auth} 패키지를 참조하는 것이 맞다.</b> 계정 갱신과
	 * RefreshToken 삭제를 한 로컬 트랜잭션으로 묶어야 하므로 두 패키지 사이에 단방향 제약을 두지
	 * 않는다 (sp-docs/plan/phase1.md §2.5, sp-docs/conventions.md §1.1).
	 */
	private final RefreshTokenRepository refreshTokenRepository;

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

	/**
	 * MR-09 — 비밀번호 변경 (sp-docs/api-contract.md §2.2, sp-docs/security.md §7).
	 *
	 * <p><b>비밀번호 교체와 Refresh Token 삭제가 한 로컬 트랜잭션이다</b>
	 * (sp-docs/requirements/member.md §3 규칙 4). 둘로 나누면 한쪽만 반영된 상태가 남는다 —
	 * 비밀번호는 바뀌었는데 옛 Refresh Token 이 14일간 살아 있거나, 세션만 끊기고 비밀번호는
	 * 그대로이거나.
	 *
	 * <p><b>Access Token 은 지울 수 없다.</b> 이미 발급된 것은 만료까지 보호 경로를 통과한다 —
	 * "비밀번호를 바꿨으니 안전하다"는 최대 31분 뒤부터 참이다. 즉시 차단은 1차 범위 밖이고
	 * 탈퇴·권한 회수와 같은 포기 목록에 있다 (sp-docs/security.md §5.3).
	 *
	 * <p><b>더미 해시 비교를 넣지 않는다.</b> 응답 시간을 맞추는 것은 로그인 전용이다 — 거기서는
	 * 이메일의 존재 여부를 숨겨야 하지만, 이 요청은 이미 인증되어 있어 자기 계정의 존재가
	 * 전제이므로 숨길 것이 없다 (sp-docs/security.md §4.1 마지막 문단).
	 *
	 * <p><b>탈퇴한 계정은 404 {@code AU001} 로 거부한다</b> (sp-docs/api-contract.md §2.2 v10).
	 * Access Token 이 탈퇴 후에도 만료까지 통과하므로(§5.3) 실제로 도달 가능한 경로다.
	 *
	 * <p><b>권한 상승을 막는 것이 아니다.</b> 바꿔도 새 세션은 만들 수 없다 — 로그인·재발급이
	 * {@code deleted} 를 보고, 이메일은 재사용되지 않는다. 막는 이유는 남는 상태 둘이다.
	 * {@code account.password} 는 닫힌 행의 자격증명이 요청자가 정한 값으로 덮이는 것이고(복구가
	 * 2차에 생기면 원래 소유자의 비밀번호로 복구되지 않는다), {@code account.updated_at} 은
	 * 갱신되어 <b>탈퇴 시점의 유일한 흔적이 지워지는 것</b>이다 — {@code account} 에
	 * {@code deleted_at} 컬럼이 없다(1차의 알려진 한계).
	 *
	 * <p><b>이 검사를 {@code AccountReader} 에 두지 않는다.</b> 거기서 일괄 거부하면
	 * {@code DELETE /accounts/me} 의 멱등성이 깨진다 — 그쪽은 이미 탈퇴한 계정에도 204 다.
	 * 검사는 기능별로 한다 (sp-docs/requirements/member.md §3 규칙 5).
	 *
	 * <p><b>새 비밀번호가 현재와 같아도 거부하지 않는다</b> (sp-docs/api-contract.md §2.2).
	 * 비교하려면 BCrypt 를 한 번 더 돌려야 하고, 같은 값으로 바꾸는 것이 해롭지 않다 —
	 * RefreshToken 은 어차피 삭제되어 세션이 끊긴다.
	 *
	 * @param accountId 검증된 Access Token 의 {@code sub}. 본문의 식별자를 쓰지 않는다
	 *         (sp-docs/security.md §4)
	 */
	@Transactional
	public void changePassword(Long accountId, PasswordChangeRequest request) {
		Account account = this.accountReader.getById(accountId);

		// 탈퇴한 계정은 없는 계정과 같이 다룬다 (sp-docs/api-contract.md §2.2 v10).
		// 비밀번호 비교보다 먼저다 — 틀린 비밀번호로 와도 AU001 이어야 닫힌 행에
		// 쓰기가 닿지 않고, updated_at 도 움직이지 않는다
		if (!account.isActive()) {
			throw new BusinessException(ErrorCode.ACCOUNT_NOT_FOUND);
		}

		// 값이 틀리면 AU004 다. 형식으로 가르지 않는다
		// (sp-docs/api-contract.md §2.2, sp-docs/plan/phase1.md §4 AU-08 검증표).
		//
		// 누락·null·빈 값을 여기서 걸러 AU004 로 보내지 않는다. §2.2 의 표가 그 입력을
		// 400 C001 로 못박았고, 이유는 "AU004 의 메시지는 아무것도 보내지 않은 요청에는
		// 거짓이다"다 — 서비스에서 AU004 로 바꾸면 정본이 배제한 매핑이 생긴다.
		// HTTP 경로에서는 PasswordChangeRequest 의 @NotBlank 가 컨트롤러 앞에서 끊고,
		// 서비스를 직접 호출하는 호출자는 이 저장소에 없다.
		//
		// null 이 들어오면 matches 가 IllegalArgumentException 을 던진다. 그것이 정직하다 —
		// 업무 오류가 아니라 호출자의 프로그래밍 오류다
		if (!this.passwordEncoder.matches(request.currentPassword(), account.getPassword())) {
			throw new BusinessException(ErrorCode.PASSWORD_MISMATCH);
		}

		// 평문을 저장하지 않는다. 해싱은 서비스 계층의 몫이다 (sp-docs/plan/phase1.md §4 AU-08)
		account.changePassword(this.passwordEncoder.encode(request.newPassword()));

		// 같은 트랜잭션이다. 멱등이므로 저장된 행이 없어도 지울 것이 없을 뿐이다
		this.refreshTokenRepository.deleteByAccountId(accountId);
	}

}
