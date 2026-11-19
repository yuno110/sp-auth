package com.example.auth.account.controller;

import com.example.auth.account.dto.AccountCreateRequest;
import com.example.auth.account.dto.AccountMeResponse;
import com.example.auth.account.dto.AccountResponse;
import com.example.auth.account.dto.AccountSearchCondition;
import com.example.auth.account.dto.AccountSortType;
import com.example.auth.account.dto.AccountSummaryResponse;
import com.example.auth.account.dto.CheckResponse;
import com.example.auth.account.dto.EmailRequest;
import com.example.auth.account.dto.PasswordChangeRequest;
import com.example.auth.account.dto.PasswordResetConfirmRequest;
import com.example.auth.account.dto.TokenConfirmRequest;
import com.example.auth.account.dto.WithdrawRequest;
import com.example.auth.account.entity.Role;
import com.example.auth.account.service.AccountService;
import com.example.auth.global.common.ApiResponse;
import com.example.auth.global.common.PageResponse;
import com.example.auth.global.ratelimit.RateLimitRule;
import com.example.auth.global.ratelimit.RateLimiter;
import com.example.auth.global.security.CurrentAccount;
import com.example.auth.global.security.LoginAccount;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * 계정 API. 정본: sp-docs/api-contract.md §2.2.
 *
 * <p>여러 작업 항목이 확장하는 공유 지점이다 — 이 파일을 고치는 항목은 계획의 표가 적는다(sp-docs/plan/phase1.md §2.3,
 * sp-docs/plan/phase2-auth-member.md §1.2). 어느 항목이 무엇을 더했는지는 git 이력이 답한다.
 *
 * <p>경로별 인가는 AU-04 의 {@code SecurityConfig} 가 선반영했다 — {@code POST /api/v1/accounts}
 * 는 무인증이다 (sp-docs/security.md §5.1).
 *
 * <p>요청 수 제한의 IP 키는 여기서 세지 않는다 — {@code RateLimitInterceptor} 가 핸들러 앞에서 센다
 * (sp-docs/security.md §10).
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/accounts")
public class AccountController {

	private final AccountService accountService;

	/** 재발송·재설정 요청의 이메일 키를 센다 (sp-docs/security.md §10). */
	private final RateLimiter rateLimiter;

	/**
	 * 가입 1단계. 201 과 {@code {accountId, email}} (sp-docs/api-contract.md §9.1). 계정 INSERT 가 커밋된 뒤 인증 메일이
	 * 나간다 (§2.2, sp-docs/requirements/member.md §11.2).
	 */
	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public ApiResponse<AccountResponse> create(@Valid @RequestBody AccountCreateRequest request) {
		return ApiResponse.success(this.accountService.create(request));
	}

	/**
	 * MR-14 — 인증 메일 재발송. <b>202</b> 와 {@code {success: true, data: null, error: null}}
	 * (sp-docs/api-contract.md §2.4 §9.10). 무인증이다.
	 *
	 * <p><b>202 가 계정의 상태를 말하지 않는다.</b> 계정이 없다·탈퇴했다·인증됐다·아니다 어느 경우든 같은 상태와
	 * 본문이다 — 메일이 나가는지는 뒤의 발급 작업이 정한다. 202 가 아닌 응답은 sp-docs/api-contract.md §2.4 의 표가
	 * 정한다 — {@code email} 의 형식 위반은 400 {@code C001} 이다 ({@link EmailRequest}).
	 *
	 * <p><b>이메일 키는 본문 검증 뒤·발급 작업 앞에서 센다</b> (sp-docs/security.md §10). 형식 위반은 이 메서드에 닿지 않아
	 * 이메일 키로 세지 않는다. 한도를 넘으면 429 {@code C009} 이고 발급 작업을 넘기지 않는다. 키는 계정을 찾지 않고 요청의
	 * 이메일만으로 정하므로 429 도 계정의 상태로 갈리지 않는다.
	 */
	@PostMapping("/email-verification")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public ApiResponse<Void> resendVerification(@Valid @RequestBody EmailRequest request) {
		this.rateLimiter.consume(RateLimitRule.VERIFICATION_EMAIL, emailKeyOf(request.email()));
		this.accountService.resendVerification(request.email());
		return ApiResponse.success(null);
	}

	/**
	 * MR-14 — 이메일 인증 확인. <b>204, 본문 없음</b> (sp-docs/api-contract.md §2.4 §9.10). 무인증이다 — 링크를 연
	 * 브라우저가 로그인돼 있지 않아도 된다 (sp-docs/requirements/member.md §11.2).
	 *
	 * <p>{@code token} 누락·빈 값은 400 {@code C001}({@link TokenConfirmRequest}), 토큰이 없다·만료됐다·이미
	 * 쓰였다·목적이 다르다·그 계정이 탈퇴했다는 모두 400 {@code AU007} 이다. <b>토큰(Access·Refresh)을 주지 않는다</b> —
	 * 로그인은 따로 한다.
	 */
	@PostMapping("/email-verification/confirm")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void confirmVerification(@Valid @RequestBody TokenConfirmRequest request) {
		this.accountService.confirmEmailVerification(request.token());
	}

	/**
	 * MR-15 — 비밀번호 재설정 요청. <b>202</b> 와 {@code {success: true, data: null, error: null}}
	 * (sp-docs/api-contract.md §2.4 §9.11). 무인증이다.
	 *
	 * <p>{@link #resendVerification} 과 같은 모양이다 — 202 가 계정의 상태를 말하지 않는다. 계정이 없다·탈퇴했다·인증됐다·
	 * 아니다 어느 경우든 같은 상태와 본문이고, 메일이 나가는지는 뒤의 발급 작업이 정한다. {@code email} 의 형식 위반은
	 * 400 {@code C001} 이다 ({@link EmailRequest}). 요청만으로는 세션·잠금·비밀번호가 바뀌지 않는다
	 * (sp-docs/requirements/member.md §11.3). 이메일 키도 재발송과 같은 자리에서 센다 — 규칙만 다르다.
	 */
	@PostMapping("/password-reset")
	@ResponseStatus(HttpStatus.ACCEPTED)
	public ApiResponse<Void> requestPasswordReset(@Valid @RequestBody EmailRequest request) {
		this.rateLimiter.consume(RateLimitRule.PASSWORD_RESET_EMAIL, emailKeyOf(request.email()));
		this.accountService.requestPasswordReset(request.email());
		return ApiResponse.success(null);
	}

	/**
	 * MR-16 — 비밀번호 재설정 확인. <b>204, 본문 없음</b> (sp-docs/api-contract.md §2.4 §9.11). 무인증이다.
	 *
	 * <p>{@code token} 누락·빈 값과 {@code newPassword} 의 비밀번호 규칙 위반은 400 {@code C001} 이고
	 * ({@link PasswordResetConfirmRequest}), 이 검증이 서비스보다 먼저 돌아 위반한 요청은 토큰을 쓰지 않는다. 토큰이
	 * 없다·만료됐다·이미 쓰였다·목적이 다르다·그 계정이 탈퇴했다는 모두 400 {@code AU007} 이다. <b>토큰(Access·Refresh)을
	 * 주지 않는다</b> — 로그인은 새 비밀번호로 따로 한다.
	 */
	@PostMapping("/password-reset/confirm")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmRequest request) {
		this.accountService.confirmPasswordReset(request.token(), request.newPassword());
	}

	/**
	 * MR-13 — 계정 목록 (ADMIN). 200 과 §7.1 의 페이징 모양 (sp-docs/api-contract.md §2.5 §9.12).
	 *
	 * <p><b>인증이 필요하다</b> — 경로 인가는 AU-04 의 {@code SecurityConfig} 가 {@code GET /api/v1/accounts} 로 선반영했고 토큰
	 * 없는 접근은 401 {@code A001} 이다. ADMIN 판정은 Service 가 한다(아니면 403 {@code A004}).
	 *
	 * <p>{@code page} 음수·{@code size} 1 미만·{@code email} {@value AccountSearchCondition#EMAIL_MAX_LENGTH}자 초과는 여기의
	 * 파라미터 제약이 400 {@code C001}·{@code fieldErrors} 1건으로 거른다 — 담을 파라미터 이름을 아는 자리이고,
	 * {@code PageRequest.of} 보다 앞이다. {@code sort}·{@code role}·{@code deleted} 의 틀린 값은 바인딩 실패라 400
	 * {@code C002} 다. 이 검증은 ADMIN 판정보다 먼저 돈다 — 정본이 그 순서를 받아들인다(§2.5).
	 */
	@GetMapping
	public ApiResponse<PageResponse<AccountSummaryResponse>> getList(
			@CurrentAccount LoginAccount loginAccount,
			@RequestParam(required = false) @Min(AccountSearchCondition.MIN_PAGE) Integer page,
			@RequestParam(required = false) @Min(AccountSearchCondition.MIN_SIZE) Integer size,
			@RequestParam(required = false) AccountSortType sort,
			@RequestParam(required = false) @Size(max = AccountSearchCondition.EMAIL_MAX_LENGTH) String email,
			@RequestParam(required = false) Role role,
			@RequestParam(required = false) Boolean deleted) {

		return ApiResponse.success(this.accountService.getList(
				loginAccount, AccountSearchCondition.of(page, size, sort, email, role, deleted)));
	}

	/**
	 * 이메일 중복 확인. 200 과 {@code {available}} (sp-docs/api-contract.md §2.3).
	 *
	 * <p><b>파라미터에 생성과 같은 이메일 규칙을 적용한다</b> (§2.3). 누락·빈 값·형식 오류·길이
	 * 초과는 모두 400 {@code C001} 이다. 형식 오류에 {@code available: true} 를 돌려주면 쓸 수
	 * 없는 값을 쓸 수 있다고 답하는 셈이고, 클라이언트가 생성에서 400 을 받아 같은 판정을 두 번
	 * 하게 된다.
	 *
	 * <p>메시지와 길이는 {@link AccountCreateRequest} 의 상수를 그대로 쓴다 — 규칙을 두 군데
	 * 적지 않기 위해서다. 누락은 {@code MissingServletRequestParameterException},
	 * 나머지는 메서드 검증이 걸러낸다 (둘 다 {@code GlobalExceptionHandler} 가 {@code C001} 로 변환).
	 */
	@GetMapping("/check-email")
	public ApiResponse<CheckResponse> checkEmail(
			@RequestParam
			@NotBlank(message = AccountCreateRequest.EMAIL_MESSAGE)
			@Email(message = AccountCreateRequest.EMAIL_MESSAGE)
			@Size(max = AccountCreateRequest.EMAIL_MAX_LENGTH, message = AccountCreateRequest.EMAIL_MESSAGE)
			String email) {

		return ApiResponse.success(this.accountService.checkEmail(email));
	}

	/**
	 * MR-07 — 내 계정 조회. 200 과 {@code {email, createdAt}} (sp-docs/api-contract.md §2.2).
	 *
	 * <p><b>인증이 필요하다.</b> 조회 대상은 검증된 Access Token 의 {@code sub} 가 정한다 —
	 * 파라미터·본문의 식별자를 신뢰하지 않으므로 타인의 {@code accountId} 를 실어 보내도
	 * 무시된다 (sp-docs/security.md §4). 경로 인가는 AU-04 의 {@code SecurityConfig} 가
	 * {@code /api/v1/accounts/me} 로 선반영했고, 토큰 없는 접근은 401 {@code A001} 이다.
	 *
	 * <p><b>탈퇴한 계정의 토큰으로 오면 404 {@code AU001} 이다</b> — Access Token 은 탈퇴 후에도
	 * 만료까지 통과한다 (sp-docs/security.md §5.3). {@code DELETE /accounts/me} 만 그 경우에 204
	 * 이고(멱등이 요구사항이다), 조회·변경은 404 다 (sp-docs/api-contract.md §2.2 의 표).
	 *
	 * <p>응답 형태는 {@link AccountMeResponse} 가 고정한다.
	 */
	@GetMapping("/me")
	public ApiResponse<AccountMeResponse> me(@CurrentAccount LoginAccount loginAccount) {
		return ApiResponse.success(this.accountService.getMe(loginAccount.accountId()));
	}

	/**
	 * MR-09 — 비밀번호 변경. <b>204, 본문 없음</b> (sp-docs/api-contract.md §2.2).
	 *
	 * <p><b>인증이 필요하다.</b> 바꿀 대상은 검증된 Access Token 의 {@code sub} 가 정한다 —
	 * 본문의 식별자를 신뢰하지 않는다 (sp-docs/security.md §4). 경로 인가는 AU-04 의
	 * {@code SecurityConfig} 가 {@code /api/v1/accounts/me/**} 로 선반영했다.
	 *
	 * <p>{@code @Valid} 가 보는 것은 {@code newPassword} 뿐이다 — {@code currentPassword} 에
	 * 제약을 걸지 않는 이유는 {@link PasswordChangeRequest} 에 있다. {@code newPassword} 위반은
	 * 400 {@code C001} 이고 {@code fieldErrors} 에 {@code newPassword} 가 담긴다
	 * ({@code GlobalExceptionHandler}), 현재 비밀번호 불일치는 400 {@code AU004} 다
	 * (sp-docs/api-contract.md §2.2 — <b>401 이 아니다.</b> 요청자는 이미 인증되어 있고 틀린 것은
	 * 본문의 값이다).
	 */
	@PatchMapping("/me/password")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void changePassword(
			@CurrentAccount LoginAccount loginAccount,
			@Valid @RequestBody PasswordChangeRequest request) {

		this.accountService.changePassword(loginAccount.accountId(), request);
	}

	/**
	 * MR-10 1단계 — 계정 탈퇴. <b>204, 본문 없음</b> (sp-docs/api-contract.md §2.2).
	 *
	 * <p><b>본문에 현재 비밀번호를 받아 재확인한다</b> — 필드는 {@code password} 다
	 * ({@link WithdrawRequest}). 탈퇴 대상은 검증된 Access Token 의 {@code sub} 가 정한다
	 * (sp-docs/security.md §4). 경로 인가는 AU-04 의 {@code SecurityConfig} 가
	 * {@code /api/v1/accounts/me} 로 선반영했다.
	 *
	 * <p>누락·{@code null}·빈 값은 400 {@code C001} 이고 {@code fieldErrors} 에
	 * {@code password} 가 담긴다 ({@code GlobalExceptionHandler}), 값 불일치는 400
	 * {@code AU004} 다. <b>이미 탈퇴한 계정은 비밀번호를 검증하지 않고 204 다</b> — 멱등이
	 * 요구사항이다 (MR-10, sp-docs/api-contract.md §2.2).
	 *
	 * <p><b>2단계(프로필 삭제)를 여기서 호출하지 않는다.</b> 클라이언트가
	 * {@code DELETE /api/v1/members/me} 를 이어서 호출한다 — auth 는 다른 서비스를 호출하지
	 * 않는다 (sp-docs/architecture.md §5).
	 */
	@DeleteMapping("/me")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void withdraw(
			@CurrentAccount LoginAccount loginAccount,
			@Valid @RequestBody WithdrawRequest request) {

		this.accountService.withdraw(loginAccount.accountId(), request);
	}

	/**
	 * 요청 수 제한의 이메일 키 — 본문 검증을 지난 이메일을 {@link Locale#ROOT} 로 소문자로 바꾼 값이다
	 * (sp-docs/security.md §10). 로그인 잠금의 키({@code LoginAttempt#emailKeyOf}, ASCII 만 바꾼다)와 다른 변환이다 — 섞어
	 * 쓰지 않는다 (sp-docs/plan/phase2-auth-member.md AU-19).
	 */
	private static String emailKeyOf(String email) {
		return email.toLowerCase(Locale.ROOT);
	}

}
