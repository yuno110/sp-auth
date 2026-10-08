package com.example.auth.auth.service;

import com.example.auth.account.entity.Account;
import com.example.auth.account.repository.AccountRepository;
import com.example.auth.auth.dto.LoginRequest;
import com.example.auth.auth.dto.TokenResponse;
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.auth.repository.RefreshTokenRepository;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import com.example.auth.global.security.JwtTokenProvider;
import java.time.LocalDateTime;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/**
 * 세션·토큰 유스케이스. 정본: sp-docs/requirements/member.md §1 (MR-04),
 * sp-docs/security.md §4, sp-docs/api-contract.md §2.1 §9.2.
 *
 * <p>AU-06 이 만들고 AU-07(재발급·로그아웃)이 확장한다 (sp-docs/plan/phase1.md §2.3).
 *
 * <p><b>프로필 존재를 보지 않는다.</b> "계정만 있고 프로필이 없는 상태"는 정상이며 그 상태에서
 * 로그인이 되어야 한다 (sp-docs/requirements/member.md §3 규칙 3). auth 는 프로필을 소유하지
 * 않으므로 확인할 수단도 없다 — 이 클래스에 member 를 호출하는 경로가 없는 것이 그 구현이다.
 */
@Service
public class AuthService {

	private final AccountRepository accountRepository;
	private final RefreshTokenRepository refreshTokenRepository;

	/** BCrypt strength 10. 빈은 AU-04 의 {@code SecurityConfig} 가 만든다 (sp-docs/security.md §1). */
	private final PasswordEncoder passwordEncoder;

	/** 서명은 AU-04 의 산출물에 맡긴다. Claim 계약은 sp-docs/api-contract.md §6 이다. */
	private final JwtTokenProvider jwtTokenProvider;

	/**
	 * 계정이 없거나 탈퇴했을 때 비교 대상으로 쓰는 더미 해시. 결과는 쓰지 않고 버린다
	 * (sp-docs/security.md §4.1).
	 *
	 * <p><b>상수로 두지 않는다.</b> 기동 시 임의 값으로 한 번 인코딩해 메모리에만 둔다 —
	 * BCrypt 모양의 리터럴을 커밋하면 sp-docs/requirements/member.md §10.2 에 걸리고, 어떤
	 * 비밀번호의 해시도 아니어야 한다.
	 */
	private final String dummyPasswordHash;

	public AuthService(
			AccountRepository accountRepository,
			RefreshTokenRepository refreshTokenRepository,
			PasswordEncoder passwordEncoder,
			JwtTokenProvider jwtTokenProvider) {

		this.accountRepository = accountRepository;
		this.refreshTokenRepository = refreshTokenRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtTokenProvider = jwtTokenProvider;
		// 맞출 평문이 없는 값이어야 한다. 기동마다 달라도 무해하다 — 비교 시간만 필요하다
		this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
	}

	/**
	 * MR-04 — 로그인 (sp-docs/security.md §4).
	 *
	 * <p>검증과 저장이 <b>한 트랜잭션</b>이다. 그래서 인증에 실패하면 {@code refresh_token} 에
	 * 행이 생기지 않는다 — 실패 경로는 {@link #authenticate} 에서 예외로 끝나고, 롤백이 두 번째
	 * 방어선이다.
	 */
	@Transactional
	public TokenResponse login(LoginRequest request) {
		Account account = authenticate(request);

		TokenResponse tokens = this.jwtTokenProvider.issue(account.getId(), account.getRole());
		storeRefreshToken(account.getId(), tokens.refreshToken());
		return tokens;
	}

	/**
	 * 이메일·비밀번호를 검증한다.
	 *
	 * <p><b>실패 이유를 구분해 내보내지 않는다.</b> 없는 이메일·비밀번호 불일치·탈퇴 계정이 모두
	 * 같은 {@code AU003}(401, 같은 메시지)이다 (sp-docs/plan/phase1.md §4 AU-06). 구분하면 이메일
	 * 존재 여부를 알려주는 열거 취약점이 된다. 그래서 <b>로그도 남기지 않는다</b> — 정본은 로그인
	 * 실패의 로깅을 요구하지 않고(sp-docs/nfr.md §5, sp-docs/conventions.md §8), 실패 5회 잠금은
	 * 2차 범위다(sp-docs/requirements/member.md §3 규칙 9). {@code GlobalExceptionHandler} 가
	 * 남기는 것은 에러 코드 하나이므로 세 경로가 로그에서도 구분되지 않는다.
	 *
	 * <p><b>응답 시간으로도 구분되지 않는다</b> (sp-docs/security.md §4.1). 계정이 없거나
	 * 탈퇴했을 때 BCrypt 비교를 건너뛰면 그 경로만 48ms 빨라져 이메일 존재 여부가 드러난다.
	 * 그래서 <b>세 실패 경로가 모두 {@code matches} 를 정확히 한 번 수행한다</b> — 비교 대상이
	 * 없을 때는 {@link #dummyPasswordHash} 를 쓰고 결과를 버린다. 불일치와 정상이 구분되지 않는
	 * 것은 BCrypt 비교 자체가 보장한다.
	 */
	private Account authenticate(LoginRequest request) {
		// 자격증명이 비어 있으면 조회하지 않는다. matches() 에 null 을 넘기면
		// IllegalArgumentException 이 500 C005 로 새어 나간다.
		// 이 경로는 계정에 대해 아무것도 알려주지 않으므로 시간을 맞출 대상이 아니다
		if (!StringUtils.hasText(request.email()) || !StringUtils.hasText(request.password())) {
			throw loginFailed();
		}

		// 탈퇴 계정을 "없음"과 같은 자리에 둔다. 여기서 갈라 비교를 건너뛰면 "그 이메일은
		// 존재하되 탈퇴했다"가 시간으로 드러난다 (sp-docs/security.md §4.1).
		// 탈퇴 계정 거부 자체는 sp-docs/requirements/member.md §3 규칙 5 가 요구한다
		Account account = this.accountRepository.findByEmail(request.email())
				.filter(Account::isActive)
				.orElse(null);

		// 비교를 조건부로 만들지 않는다. 계정이 없으면 더미 해시와 비교하고 결과를 버린다
		boolean matched = this.passwordEncoder.matches(
				request.password(),
				(account != null) ? account.getPassword() : this.dummyPasswordHash);

		if (account == null || !matched) {
			throw loginFailed();
		}
		return account;
	}

	/**
	 * 발급한 Refresh Token 을 {@code sp_auth} 에 저장한다. <b>계정당 1행이다</b>
	 * (sp-docs/domain-model.md §2.2). 재로그인하면 행이 늘지 않고 값이 교체된다 —
	 * 그것을 최종적으로 보장하는 것은 {@code uk_refresh_account_id} 다 (§2.3).
	 *
	 * <p><b>조건부 UPDATE({@code rotate})를 쓰지 않는다.</b> 정본이 조건부 UPDATE 와 "0행이면
	 * 실패"를 요구하는 대상은 <b>재발급</b>이다 (sp-docs/requirements/member.md §6,
	 * sp-docs/domain-model.md §2.2). 거기서는 저장된 행 자체가 자격증명이므로 행이 사라진 뒤에
	 * 쓰면 탈퇴로 지운 행이 되살아난다. 로그인의 자격증명은 이메일·비밀번호이고 저장된 행에는
	 * 아무 권한도 걸지 않으므로, "옛 행이 있어야 쓸 수 있다"는 조건이 성립할 대상이 없다.
	 *
	 * <p><b>기존 행을 찾아 갱신한다. 지우고 다시 넣지 않는다.</b> 재삽입은 로그인마다
	 * {@code refresh_token.id} 를 AUTO_INCREMENT 로 올리고 인덱스를 흔든다 —
	 * 재로그인 후에도 {@code id} 가 같아야 한다 (sp-docs/plan/phase1.md §4 AU-06).
	 * 영속 상태의 엔티티를 바꾸면 더티 체킹이 커밋 시점에 UPDATE 를 보낸다.
	 *
	 * <p>{@code expires_at} 은 Refresh Token 만료(14일)다 (sp-docs/security.md §1). 시간대는
	 * 실행 환경이 정한다 (sp-docs/adr/0011).
	 */
	private void storeRefreshToken(Long accountId, String refreshToken) {
		LocalDateTime expiresAt =
				LocalDateTime.now().plus(this.jwtTokenProvider.getRefreshTokenValidity());

		this.refreshTokenRepository.findByAccountId(accountId).ifPresentOrElse(
				existing -> existing.renew(refreshToken, expiresAt),
				() -> this.refreshTokenRepository.saveAndFlush(RefreshToken.builder()
						.accountId(accountId)
						.token(refreshToken)
						.expiresAt(expiresAt)
						.build()));
	}

	/** 세 실패 경로가 같은 예외를 쓴다. 분기마다 만들면 언젠가 메시지가 갈린다. */
	private static BusinessException loginFailed() {
		return new BusinessException(ErrorCode.LOGIN_FAILED);
	}

}
