package com.example.auth.account.service;

import com.example.auth.account.dto.AccountCreateRequest;
import com.example.auth.account.dto.AccountMeResponse;
import com.example.auth.account.dto.AccountResponse;
import com.example.auth.account.dto.AccountSearchCondition;
import com.example.auth.account.dto.AccountSummaryResponse;
import com.example.auth.account.dto.CheckResponse;
import com.example.auth.account.dto.PasswordChangeRequest;
import com.example.auth.account.dto.WithdrawRequest;
import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.Role;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.account.repository.AccountQueryRepository;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.account.repository.AccountTokenRepository;
import com.example.auth.account.support.AccountReader;
import com.example.auth.account.support.AccountTokens;
import com.example.auth.auth.entity.LoginAttempt;
import com.example.auth.auth.repository.LoginAttemptRepository;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.auth.service.LoginAttemptService;
import com.example.auth.global.common.PageResponse;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.global.security.LoginAccount;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 계정 유스케이스. 정본: sp-docs/requirements/member.md §1 §2 §4,
 * sp-docs/api-contract.md §2.2 §9.1.
 *
 * <p>AU-05 가 만들고 AU-08·AU-09·AU-10 이 확장한다 (sp-docs/plan/phase1.md §2.3). 2차의 AU-16 이 가입 뒤 발급과
 * 인증 메일 재발송·확인을 더했다 (sp-docs/plan/phase2-auth-member.md, sp-docs/requirements/member.md §11.2). AU-17 이
 * 비밀번호 재설정 요청·확인을 더했다 (sp-docs/requirements/member.md §11.3·§11.4).
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
	 * 링크 메일의 발급 작업. 이 클래스는 작업을 넘기기만 하고 계정 찾기·토큰·메일은 그 작업이 한다 (AU-15,
	 * sp-docs/requirements/member.md §11.5).
	 */
	private final AccountTokenIssuer accountTokenIssuer;

	/** 링크 토큰 확인의 사용 처리 (sp-docs/requirements/member.md §11.1). */
	private final AccountTokenRepository accountTokenRepository;

	/**
	 * 재설정 확인이 그 계정 이메일의 로그인 잠금을 푼다 (sp-docs/requirements/member.md §11.4·§12.2). 해제 문장과 키 변환은
	 * AU-12 의 것을 쓴다 ({@link LoginAttemptRepository#reset}, {@link LoginAttempt#emailKeyOf}).
	 */
	private final LoginAttemptRepository loginAttemptRepository;

	/** 앱 시계. 판정과 기록의 시각이 이 시계에서 나온다 — DB 의 {@code NOW()} 를 쓰지 않는다 (§11.1). */
	private final Clock clock;

	/** 계정 목록의 조건·정렬·페이징 (AU-20, sp-docs/api-contract.md §2.5). */
	private final AccountQueryRepository accountQueryRepository;

	/**
	 * 계정 목록의 {@code locked} — 로그인이 쓰는 잠금 판정 그대로다 (AU-20). 키는 AU-12 의 변환, 시각은 주입한 {@code Clock} 이고
	 * 둘 다 그 빈이 갖는다.
	 */
	private final LoginAttemptService loginAttemptService;

	/** 계정 목록의 읽기 전용 트랜잭션 (AU-20) — {@code getList} 가 목록과 개수만 그 안에서 읽는다. */
	private final PlatformTransactionManager transactionManager;

	/**
	 * 가입 1단계 — 계정 생성 (sp-docs/requirements/member.md §4).
	 *
	 * <p>이메일이 이미 쓰이고 있으면 {@code AU002}(409)다. <b>탈퇴한 계정도 여기에 걸린다</b> —
	 * {@code deleted = true} 인 행이 남아 있고 {@code existsByEmail} 이 탈퇴 여부를 보지 않으므로
	 * 재가입이 막힌다 (sp-docs/requirements/member.md §3 규칙 1).
	 *
	 * <p><b>계정 INSERT 가 커밋된 뒤에 인증 메일 발급을 넘긴다</b> (sp-docs/requirements/member.md §11.2).
	 * 이 트랜잭션이 되돌려지면 넘기지 않으므로 메일도 없다. 요청·응답(201, 중복이면 409 {@code AU002})은 그대로다
	 * (sp-docs/api-contract.md §2.2). 만든 계정은 인증 전에 로그인할 수 없다 (§3 규칙 11).
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

		Account saved;
		try {
			// saveAndFlush 다. save 만 하면 제약 위반이 커밋 시점(이 메서드 밖)에 터져
			// DataIntegrityViolationException 이 500 C005 로 새어 나간다
			saved = this.accountRepository.saveAndFlush(account);
		} catch (DataIntegrityViolationException e) {
			// 위 검사와 INSERT 사이에 다른 요청이 같은 이메일을 선점한 경우다.
			// uk_account_email 이 최종 방어선이고, 사용자에게는 중복과 같은 상황이므로 AU002 다
			throw new BusinessException(ErrorCode.EMAIL_DUPLICATED);
		}

		// 이 트랜잭션에 거는 것이다 — 커밋되면 그때 발급 작업이 발송 실행기로 넘어가고, 되돌려지면 넘어가지 않는다.
		// 바깥 트랜잭션에 참여한 호출이면 그 바깥의 커밋을 기다린다
		this.accountTokenIssuer.requestAfterCommit(TokenPurpose.EMAIL_VERIFICATION, saved.getId());
		return AccountResponse.from(saved);
	}

	/**
	 * MR-14 — 인증 메일 재발송 (sp-docs/requirements/member.md §11.2, sp-docs/api-contract.md §2.4).
	 *
	 * <p><b>이 메서드는 DB 일을 하지 않는다.</b> 발급 작업을 발송 실행기에 넘기기만 하고, 계정 찾기·보낼 조건(활성이고
	 * 미인증)·토큰·메일은 그 작업이 한다 — 응답 시간이 계정의 유무로 갈리지 않는다 (sp-docs/security.md §12). 할 DB 일이
	 * 없으므로 {@code @Transactional} 을 두지 않는다.
	 *
	 * <p>계정이 없거나 탈퇴했거나 이미 인증됐어도 실패가 아니다 — 응답은 언제나 같은 202 다.
	 *
	 * @param email 요청에 실린 문자열. 메일은 이 표기가 아니라 계정에 저장된 주소로 간다 (§11.3)
	 */
	public void resendVerification(String email) {
		this.accountTokenIssuer.request(TokenPurpose.EMAIL_VERIFICATION, email);
	}

	/**
	 * MR-14 — 이메일 인증 확인 (sp-docs/requirements/member.md §11.2, sp-docs/api-contract.md §2.4).
	 *
	 * <p><b>한 트랜잭션이다.</b> 순서는 §11.2 를 따른다.
	 * <ol>
	 *   <li>토큰 사용 처리 — 조건부 UPDATE 하나가 판정한다. 0행이면 400 {@code AU007}</li>
	 *   <li>그 계정이 탈퇴했으면 되돌린다 — 400 {@code AU007}. 예외가 이 트랜잭션을 되돌려 1의 사용 처리도 없던 일이
	 *   된다</li>
	 *   <li>{@code email_verified_at} 이 NULL 이면 지금 시각으로 채운다. 이미 인증됐으면 그대로 둔다</li>
	 *   <li>같은 계정·목적의 나머지 토큰(쓴 토큰 말고)을 지운다 — 같은 트랜잭션이다. 락 예외를 삼키지 않는다 (§11.1)</li>
	 * </ol>
	 *
	 * <p>없음·만료·사용됨·목적 다름·탈퇴 계정을 가르지 않는다 — 모두 같은 {@code AU007} 이다 (§11.1). 토큰의 길이·문자가
	 * 틀려도 형식 오류가 아니라 맞지 않는 토큰이다 (sp-docs/api-contract.md §2.4).
	 *
	 * <p><b>로그인하지 않는다.</b> 토큰(Access·Refresh)을 주지 않는다 — 화면이 로그인으로 안내한다 (§11.2).
	 *
	 * @param token 메일 링크의 토큰 원문. 받은 문자열을 해시해 찾는다 — 원문은 저장돼 있지 않다
	 */
	@Transactional
	public void confirmEmailVerification(String token) {
		String tokenHash = AccountTokens.hash(token);

		// 1) 사용 처리. 읽어서 확인한 뒤 쓰지 않는다 — 같은 토큰의 동시 확인 둘이 모두 성공한다.
		// 이 문장은 영속성 컨텍스트를 비운다. 그래서 계정은 이 문장 뒤에 처음 읽는다
		if (this.accountTokenRepository.consume(tokenHash, TokenPurpose.EMAIL_VERIFICATION, this.clock) != 1) {
			throw invalidLinkToken();
		}

		// 방금 이 트랜잭션이 사용 처리한 행이다. 없다면 판정이 아니라 불변식이 깨진 것이므로 숨기지 않는다
		AccountToken used = this.accountTokenRepository.findByTokenHash(tokenHash)
				.orElseThrow(() -> new IllegalStateException("사용 처리한 토큰의 행이 없다"));
		Long accountId = used.getAccountId();

		// 잠금 읽기다 — 인증 시각의 쓰기가 탈퇴 검사가 본 값 위에 놓인다. 이유는 AccountRepository#findByIdForUpdate 에 있다.
		// 행은 있어야 한다 — fk_account_token_account(ON DELETE 절 없음, V7)가 토큰이 남은 계정의 삭제를 막는다
		Account account = this.accountRepository.findByIdForUpdate(accountId)
				.orElseThrow(() -> new IllegalStateException("토큰이 가리키는 계정의 행이 없다"));

		// 2) 탈퇴 계정. 토큰 오류와 같은 응답이다. 닫힌 행에는 쓰지 않는다
		if (!account.isActive()) {
			throw invalidLinkToken();
		}

		// 3) 처음 인증한 시각이 남는다 — 이미 채워져 있으면 덮지 않는다 (Account#markEmailVerified)
		account.markEmailVerified(this.clock);

		// 4) 같은 계정·목적의 나머지 토큰을 지운다 — 발송이 실패해 남은 앞 링크와 메일로 나가지 않은 토큰이다 (§11.1, D-28).
		// 이 문장은 3 을 flush 한 뒤 지운다. 락 예외를 잡지 않는다 — 던지면 확인 전체가 되돌려져 토큰 사용도 없던 일이
		// 된다 (500 C005). 삼켜도 응답이 상태를 말하지 않는다: Hibernate 를 거친 락 예외는 트랜잭션을 rollback-only 로 표시해
		// 커밋이 UnexpectedRollbackException 이 된다 (2026-11-24 AU-24 리뷰가 H2 의 행 락으로 확인)
		this.accountTokenRepository.deleteOthers(accountId, TokenPurpose.EMAIL_VERIFICATION, used.getId());
	}

	/**
	 * MR-15 — 비밀번호 재설정 요청 (sp-docs/requirements/member.md §11.3, sp-docs/api-contract.md §2.4).
	 *
	 * <p><b>이 메서드는 DB 일을 하지 않는다.</b> {@link #resendVerification} 과 같은 모양이다 — 발급 작업을 발송 실행기에
	 * 넘기기만 하고, 계정 찾기·보낼 조건(활성)·토큰·메일은 그 작업이 한다. 응답 시간이 계정의 유무로 갈리지 않는다
	 * (sp-docs/security.md §12). 할 DB 일이 없으므로 {@code @Transactional} 을 두지 않는다.
	 *
	 * <p>계정이 없거나 탈퇴했어도 실패가 아니다 — 응답은 언제나 같은 202 다. <b>요청만으로는 세션·잠금·비밀번호가 바뀌지
	 * 않는다</b> — 바뀌는 것은 확인({@link #confirmPasswordReset}) 때다 (§11.3).
	 *
	 * @param email 요청에 실린 문자열. 메일은 이 표기가 아니라 계정에 저장된 주소로 간다 (§11.3)
	 */
	public void requestPasswordReset(String email) {
		this.accountTokenIssuer.request(TokenPurpose.PASSWORD_RESET, email);
	}

	/**
	 * MR-16 — 비밀번호 재설정 확인 (sp-docs/requirements/member.md §11.4, sp-docs/api-contract.md §2.4).
	 *
	 * <p>{@code newPassword} 는 여기 오기 전에 비밀번호 규칙으로 걸러졌다 — 요청 본문의 검증이 컨트롤러가 이 메서드를 부르기
	 * 전에 돈다 ({@code PasswordResetConfirmRequest}). 그래서 규칙을 어긴 입력은 토큰을 쓰지 않는다 (§11.4).
	 *
	 * <p><b>한 로컬 트랜잭션이다.</b> 순서는 §11.4 를 따른다.
	 * <ol>
	 *   <li>토큰 사용 처리 — 조건부 UPDATE 하나가 판정한다. 0행이면 400 {@code AU007}</li>
	 *   <li>그 계정이 탈퇴했으면 되돌린다 — 400 {@code AU007}. 예외가 이 트랜잭션을 되돌려 1의 사용 처리도 없던 일이
	 *   된다</li>
	 *   <li>비밀번호를 새 값의 BCrypt 해시로 바꾼다</li>
	 *   <li>그 계정의 {@code refresh_token} 행을 지운다 — 비밀번호 변경(§3 규칙 4)과 같다</li>
	 *   <li>그 계정 이메일의 로그인 잠금을 푼다 (§12.2). 키는 계정에 저장된 이메일에서 만든다</li>
	 *   <li>{@code email_verified_at} 이 NULL 이면 지금 시각으로 채운다. 이미 인증됐으면 그대로 둔다</li>
	 *   <li>같은 계정·목적의 나머지 토큰(쓴 토큰 말고)을 지운다 — 같은 트랜잭션이다. 락 예외를 삼키지 않는다 (§11.1)</li>
	 * </ol>
	 * 일부만 커밋되면 비밀번호는 바뀌었는데 옛 Refresh Token 이 살거나, 토큰은 쓰였는데 비밀번호가 그대로인 상태가 남는다
	 * (§11.4).
	 *
	 * <p><b>잠금은 1 의 토큰 행 → 계정 → 4 의 {@code refresh_token} → 5 의 {@code login_attempt} → 7 의 같은 계정·목적 토큰 범위 차례로 잡는다.</b> 계정은 2 의
	 * 검사 전에 잠금 읽기로 읽는다. 계정을 잡은 뒤 {@code refresh_token} 을 잡는 것은 로그인의 저장({@code AuthService})과 같은
	 * 순서이고, 그 저장은 이 트랜잭션이 계정을 잡은 동안 오면 이 트랜잭션이 끝나기를 기다렸다가 커밋된 값과 견준다
	 * (sp-docs/plan/phase2-auth-member.md AU-22).
	 *
	 * <p>없음·만료·사용됨·목적 다름·탈퇴 계정을 가르지 않는다 — 모두 같은 {@code AU007} 이다 (§11.1). 토큰의 길이·문자가
	 * 틀려도 형식 오류가 아니라 맞지 않는 토큰이다 (sp-docs/api-contract.md §2.4).
	 *
	 * <p><b>로그인하지 않는다.</b> 토큰(Access·Refresh)을 주지 않는다. 이미 발급된 Access Token 은 만료까지 통과한다 —
	 * 비밀번호 변경과 같은 창이고, 막는 코드를 두지 않는다 (sp-docs/security.md §5.3).
	 *
	 * @param token 메일 링크의 토큰 원문. 받은 문자열을 해시해 찾는다 — 원문은 저장돼 있지 않다
	 * @param newPassword 비밀번호 규칙을 지난 평문. 저장하는 것은 그 BCrypt 해시다
	 */
	@Transactional
	public void confirmPasswordReset(String token, String newPassword) {
		String tokenHash = AccountTokens.hash(token);

		// 1) 사용 처리. 읽어서 확인한 뒤 쓰지 않는다 — 같은 토큰의 동시 확인 둘이 모두 성공한다.
		// 이 문장은 영속성 컨텍스트를 비운다. 그래서 계정은 이 문장 뒤에 처음 읽는다
		if (this.accountTokenRepository.consume(tokenHash, TokenPurpose.PASSWORD_RESET, this.clock) != 1) {
			throw invalidLinkToken();
		}

		// 방금 이 트랜잭션이 사용 처리한 행이다. 없다면 판정이 아니라 불변식이 깨진 것이므로 숨기지 않는다
		AccountToken used = this.accountTokenRepository.findByTokenHash(tokenHash)
				.orElseThrow(() -> new IllegalStateException("사용 처리한 토큰의 행이 없다"));
		Long accountId = used.getAccountId();

		// 잠금 읽기다 — 3·6 의 쓰기가 탈퇴 검사가 본 값 위에 놓인다. 이유는 AccountRepository#findByIdForUpdate 에 있다.
		// 행은 있어야 한다 — fk_account_token_account(ON DELETE 절 없음, V7)가 토큰이 남은 계정의 삭제를 막는다
		Account account = this.accountRepository.findByIdForUpdate(accountId)
				.orElseThrow(() -> new IllegalStateException("토큰이 가리키는 계정의 행이 없다"));

		// 2) 탈퇴 계정. 토큰 오류와 같은 응답이다. 닫힌 행에는 쓰지 않는다 — 이 검사가 3~6 의 쓰기보다 먼저다
		if (!account.isActive()) {
			throw invalidLinkToken();
		}

		// 3) 평문을 저장하지 않는다. 해싱은 서비스 계층의 몫이다
		account.changePassword(this.passwordEncoder.encode(newPassword));

		// 4) 같은 트랜잭션이다. 멱등이므로 저장된 행이 없어도 지울 것이 없을 뿐이다. 이 문장은 3 을 flush 한 뒤 영속성
		// 컨텍스트를 비운다 — 여기부터 account 는 준영속이다
		this.refreshTokenRepository.deleteByAccountId(accountId);

		// 5) 키는 계정에 저장된 이메일을 AU-12 의 키 변환으로 바꾼 값이다. 그 키의 행이 없으면 0행이고 실패가 아니다 —
		// 잠기지 않은 것과 결과가 같다 (LoginAttemptRepository#reset)
		this.loginAttemptRepository.reset(LoginAttempt.emailKeyOf(account.getEmail()), this.clock);

		// 6) 4 가 비운 뒤라 다시 읽어서 바꾼다 — 준영속인 account 를 바꾸면 저장되지 않는다. 이 트랜잭션이 이미 그 행을
		// 잠갔으므로 기다리지 않는다. 처음 인증한 시각이 남는다 — 이미 채워져 있으면 덮지 않는다 (Account#markEmailVerified)
		this.accountRepository.findByIdForUpdate(accountId)
				.orElseThrow(() -> new IllegalStateException("토큰이 가리키는 계정의 행이 없다"))
				.markEmailVerified(this.clock);

		// 7) 같은 계정·목적의 나머지 토큰을 지운다 — 이유는 인증 확인의 4 와 같다 (§11.4, D-28). 계정·refresh_token·login_attempt
		// 뒤, 마지막에 이 범위를 잡는다 — AU-22 의 잠금 차례는 그대로다. 락 예외를 잡지 않는다 — 확인 전체가 되돌려진다
		this.accountTokenRepository.deleteOthers(accountId, TokenPurpose.PASSWORD_RESET, used.getId());
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
	 * MR-07 — 내 계정 조회 (sp-docs/api-contract.md §2.2, sp-docs/requirements/member.md §5).
	 *
	 * <p><b>MR-07 이 두 서비스로 갈라진 절반이다.</b> 나머지 절반(닉네임)은 member 의
	 * {@code GET /api/v1/members/me} 이고, 화면 하나에 둘 다 필요하면 클라이언트가 두 번
	 * 호출한다 — auth 는 다른 서비스를 호출하지 않는다 (sp-docs/architecture.md §5).
	 *
	 * <p><b>탈퇴한 계정은 404 {@code AU001} 로 거부한다</b> (sp-docs/api-contract.md §2.2) —
	 * 탈퇴한 계정은 API 관점에서 없는 계정이다. Access Token 이 탈퇴 후에도 만료까지 통과하므로
	 * (sp-docs/security.md §5.3) 실제로 도달 가능한 경로다. {@code sub} 가 가리키는 행이 아예
	 * 없을 때도 같은 코드이고, 그쪽은 {@link AccountReader} 가 끝낸다.
	 *
	 * <p><b>이 검사를 {@code AccountReader} 에 두지 않는다.</b> 거기서 일괄 거부하면
	 * {@code DELETE /accounts/me} 의 멱등성이 깨진다 — 그쪽은 이미 탈퇴한 계정에도 204 다.
	 * 검사는 기능별로 한다 (sp-docs/requirements/member.md §3 규칙 5). {@link #changePassword}
	 * 와 {@link #withdraw} 가 각자 검사하는 것과 같은 이유이고, <b>세 곳의 중복이 의도다</b> —
	 * 결론이 엔드포인트마다 다르기 때문이다 (sp-docs/api-contract.md §2.2 의 표).
	 *
	 * @param accountId 검증된 Access Token 의 {@code sub}. 요청의 식별자를 쓰지 않는다
	 *         (sp-docs/security.md §4)
	 */
	@Transactional(readOnly = true)
	public AccountMeResponse getMe(Long accountId) {
		Account account = this.accountReader.getById(accountId);

		// 탈퇴한 계정은 없는 계정과 같이 다룬다 (sp-docs/api-contract.md §2.2).
		// AccountReader 는 행의 존재만 보므로 거부는 여기에 있어야 한다
		if (!account.isActive()) {
			throw new BusinessException(ErrorCode.ACCOUNT_NOT_FOUND);
		}

		return AccountMeResponse.from(account);
	}

	/**
	 * MR-09 — 비밀번호 변경 (sp-docs/api-contract.md §2.2, sp-docs/security.md §7).
	 *
	 * <p><b>비밀번호 교체와 Refresh Token 삭제가 한 로컬 트랜잭션이다</b>
	 * (sp-docs/requirements/member.md §3 규칙 4). 둘로 나누면 한쪽만 반영된 상태가 남는다 —
	 * 비밀번호는 바뀌었는데 옛 Refresh Token 이 14일간 살아 있거나, 세션만 끊기고 비밀번호는
	 * 그대로이거나.
	 *
	 * <p><b>계정을 잠금 읽기로 먼저 읽는다</b>({@link AccountReader#getByIdForUpdate}). 탈퇴 검사·비밀번호 비교·쓰기·
	 * {@code refresh_token} 지우기가 그 잠금 아래에 있다 — 잠그지 않고 읽으면 이 읽기 뒤에 커밋된 탈퇴를 이 쓰기가 읽어 둔
	 * {@code deleted = false} 로 덮는다. 잠금은 계정을 잡은 뒤 {@code refresh_token} 을 잡는다 — 로그인의
	 * 저장({@code AuthService})과 같은 순서다. 그 저장은 같은 계정을 잠금 읽기로 다시 읽으므로, 이 트랜잭션이 계정을 잡은 동안
	 * 오면 이 트랜잭션이 끝나기를 기다렸다가 커밋된 값과 견준다 (sp-docs/plan/phase2-auth-member.md AU-22).
	 *
	 * <p><b>Access Token 은 지울 수 없다.</b> 이미 발급된 것은 만료까지 보호 경로를 통과한다 —
	 * "비밀번호를 바꿨으니 안전하다"는 최대 31분 뒤부터 참이다. 즉시 차단은 1차 범위 밖이고
	 * 탈퇴·권한 회수와 같은 포기 목록에 있다 (sp-docs/security.md §5.3).
	 *
	 * <p><b>더미 해시 비교를 넣지 않는다.</b> 응답 시간을 맞추는 것은 로그인 전용이다 — 거기서는
	 * 이메일의 존재 여부를 숨겨야 하지만, 이 요청은 이미 인증되어 있어 자기 계정의 존재가
	 * 전제이므로 숨길 것이 없다 (sp-docs/security.md §4.1 마지막 문단).
	 *
	 * <p><b>탈퇴한 계정은 404 {@code AU001} 로 거부한다</b> (sp-docs/api-contract.md §2.2).
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
		// 잠금 읽기다 — 쓰기와 지우기가 탈퇴 검사·비교가 본 값 위에 놓인다. 이유는 AccountRepository#findByIdForUpdate 에 있다
		Account account = this.accountReader.getByIdForUpdate(accountId);

		// 탈퇴한 계정은 없는 계정과 같이 다룬다 (sp-docs/api-contract.md §2.2).
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

	/**
	 * MR-10 1단계 — 계정 탈퇴 (sp-docs/api-contract.md §2.2, sp-docs/requirements/member.md §8).
	 *
	 * <p><b>탈퇴는 2단계이고 계정이 먼저다.</b> 2단계(프로필 삭제)는 member 의
	 * {@code DELETE /api/v1/members/me} 이고 <b>클라이언트가 호출한다</b> — auth 는 다른 서비스를
	 * 모르고 프로필의 존재도 모른다 (sp-docs/architecture.md §4.4 §5). 순서를 바꾸지 않는 이유는
	 * member 가 비밀번호를 갖지 않아 <b>재확인이 구조적으로 불가능해지기</b> 때문이다.
	 *
	 * <p><b>본문의 현재 비밀번호를 재확인한다</b> (MR-10). 불일치는 400 {@code AU004} 다 —
	 * 401 이 아니다. 요청자는 이미 인증되어 있고 틀린 것은 본문의 값이다.
	 *
	 * <p><b>{@code deleted = true} 와 Refresh Token 삭제가 한 로컬 트랜잭션이다</b>
	 * (sp-docs/requirements/member.md §3 규칙 4). 둘로 나누면 <b>{@code deleted = true} 가
	 * 커밋되고 토큰이 살아남는</b> 상태가 가능해지고, 그러면 탈퇴한 계정이 14일간 토큰을 갱신한다.
	 *
	 * <p><b>계정을 잠금 읽기로 먼저 읽는다</b>({@link AccountReader#getByIdForUpdate}). 이미 탈퇴했는지의 검사·비밀번호 비교·
	 * 쓰기·{@code refresh_token} 지우기가 그 잠금 아래에 있다 — 잠그지 않고 읽으면 이 읽기 뒤에 커밋된 비밀번호 변경을 이 쓰기가
	 * 읽어 둔 해시로 덮는다. 잠금은 계정을 잡은 뒤 {@code refresh_token} 을 잡는다 — 로그인의 저장({@code AuthService})과 같은
	 * 순서다. 그 저장은 같은 계정을 잠금 읽기로 다시 읽으므로, 이 트랜잭션이 계정을 잡은 동안 오면 이 트랜잭션이 끝나기를
	 * 기다렸다가 커밋된 값과 견준다 (sp-docs/plan/phase2-auth-member.md AU-22).
	 *
	 * <p><b>행을 지우지 않는다.</b> {@code Account.withdraw()} 의 Soft Delete 다 — 행이 남고
	 * {@code uk_account_email} 이 UNIQUE 이므로 탈퇴한 이메일은 재가입에 재사용되지 않는다
	 * (§3 규칙 1).
	 *
	 * <p><b>{@code deleted} 검사가 비밀번호 비교보다 먼저다</b> (sp-docs/api-contract.md §2.2).
	 * {@code PATCH /me/password} 와 <b>같은 순서이고 결론만 반대다</b> — 그쪽은 404 로 거부하고
	 * 이쪽은 204 로 통과한다. 이유는 같다: 닫힌 행에 쓰기가 닿지 않아야 하고 {@code updated_at}
	 * 이 움직이지 않아야 한다 ({@code account} 에 {@code deleted_at} 컬럼이 없어 그것이 탈퇴
	 * 시점의 유일한 흔적이다).
	 *
	 * <p><b>이미 탈퇴한 계정은 비밀번호를 검증하지 않고 204 다</b> (§2.2 의 표). 멱등이
	 * 요구사항이고(MR-10), 재확인이 보호하는 것은 <b>계정을 닫는 행위</b>이므로 이미 닫힌
	 * 계정에는 보호할 상태가 없다. <b>실패를 숨기는 것이 아니다</b> — 아래 이른 반환은 정본이
	 * 정한 결과이고, 아무것도 바꾸지 않는 것 자체가 그 결과다.
	 *
	 * <p>탈퇴 후 로그인·재발급은 {@code AuthService} 가 {@code deleted} 를 검사해 거부한다
	 * (§3 규칙 5). 이미 발급된 Access Token 은 만료까지 통과한다 (sp-docs/security.md §5.3) —
	 * 그래서 이 메서드가 멱등이어야 하고 {@code GET}·{@code PATCH} 쪽은 404 다.
	 *
	 * @param accountId 검증된 Access Token 의 {@code sub}. 본문의 식별자를 쓰지 않는다
	 *         (sp-docs/security.md §4)
	 */
	@Transactional
	public void withdraw(Long accountId, WithdrawRequest request) {
		// 잠금 읽기다 — 쓰기와 지우기가 탈퇴 검사·비교가 본 값 위에 놓인다. 이유는 AccountRepository#findByIdForUpdate 에 있다
		Account account = this.accountReader.getByIdForUpdate(accountId);

		// 멱등이다 — 이미 탈퇴한 계정은 비밀번호를 검증하지 않고 아무것도 바꾸지 않는다
		// (sp-docs/api-contract.md §2.2). 검사가 비교보다 먼저이므로 비밀번호가 틀려도
		// AU004 가 아니라 204 다
		if (!account.isActive()) {
			return;
		}

		// 값이 틀리면 AU004 다. 형식으로 가르지 않는다 (sp-docs/api-contract.md §2.2).
		// 누락·null·빈 값은 여기에 오지 않는다 — WithdrawRequest 의 @NotBlank 가 컨트롤러
		// 앞에서 400 C001 로 끊는다. changePassword 와 같은 이유다
		if (!this.passwordEncoder.matches(request.password(), account.getPassword())) {
			throw new BusinessException(ErrorCode.PASSWORD_MISMATCH);
		}

		// 행은 남긴다 (Soft Delete)
		account.withdraw();

		// 같은 트랜잭션이다. 멱등이므로 저장된 행이 없어도 지울 것이 없을 뿐이다
		this.refreshTokenRepository.deleteByAccountId(accountId);
	}

	/** 링크 토큰의 실패가 모두 같은 예외를 쓴다. 사유를 구분해 내보내지 않는다 (sp-docs/requirements/member.md §11.1). */
	private static BusinessException invalidLinkToken() {
		return new BusinessException(ErrorCode.INVALID_LINK_TOKEN);
	}

	/**
	 * MR-13 — 계정 목록 (ADMIN). sp-docs/api-contract.md §2.5, sp-docs/requirements/member.md §13.
	 *
	 * <p><b>ADMIN 판정은 여기서 Claim 의 {@code role} 값으로 한다</b> — {@code ADMIN} 과 같을 때만 허용하고 아니면 403
	 * {@code A004} 다 (sp-docs/security.md §5.1). {@code GrantedAuthority}·{@code hasRole} 로 판정하지 않는다. 「USER 이면
	 * 거부」 로 적지 않는다 — 모르는 값이 허용 분기로 가면 안 된다 (sp-docs/tech-stack.md §2.1). 판정이 조회보다 먼저다.
	 *
	 * <p><b>{@code locked} 는 원소마다 {@link LoginAttemptService#isLocked} 로 읽는다.</b> 로그인과 같은 판정(키 변환·시계·
	 * 시각 비교)을 한 곳에 두기 위해서다. 한 번의 {@code IN} 으로 읽어 자바에서 키를 맞추면, 키 컬럼의 콜레이션이 같다고 보는 다른
	 * 표기(ASCII 밖의 대소문자)를 놓친다 (sp-docs/domain-model.md §2.5) — 원소별 조회는 그 비교를 DB 가 한다. 한 페이지는
	 * 많아야 {@value AccountSearchCondition#MAX_SIZE} 건이다.
	 *
	 * <p><b>목록과 개수만 읽기 전용 트랜잭션 하나로 읽고, {@code locked} 는 그 트랜잭션이 끝난 뒤에 읽는다.</b> 조회는
	 * {@code readOnly} 트랜잭션이다 (sp-docs/conventions.md §5) — 목록과 개수가 한 스냅샷이다. {@code isLocked} 는 읽기마다
	 * 자기 트랜잭션을 연다 — 바깥 트랜잭션 안에서 부르면 한 요청이 커넥션을 둘 잡으므로 그 밖에서 부른다. 같은 빈 안의 호출이라
	 * 애노테이션이 먹지 않아 {@link TransactionTemplate} 으로 연다. 그래서 {@code locked} 는 목록보다 조금 뒤의 시점이다 —
	 * 관리 화면의 표시라 받아들인다 (sp-docs/requirements/member.md §13).
	 *
	 * @param loginAccount 검증된 Access Token 의 주체
	 */
	public PageResponse<AccountSummaryResponse> getList(LoginAccount loginAccount, AccountSearchCondition condition) {
		if (loginAccount.role() != Role.ADMIN) {
			throw new BusinessException(ErrorCode.ACCESS_DENIED);
		}
		TransactionTemplate readOnly = new TransactionTemplate(this.transactionManager);
		readOnly.setReadOnly(true);
		Page<Account> accounts = readOnly.execute(status -> this.accountQueryRepository.search(condition));
		return PageResponse.of(accounts
				.map(account -> AccountSummaryResponse.of(
						account, this.loginAttemptService.isLocked(account.getEmail()))));
	}

}
