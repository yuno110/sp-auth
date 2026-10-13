package com.example.auth.account.controller;

import com.example.auth.account.dto.AccountCreateRequest;
import com.example.auth.account.dto.AccountMeResponse;
import com.example.auth.account.dto.AccountResponse;
import com.example.auth.account.dto.CheckResponse;
import com.example.auth.account.dto.PasswordChangeRequest;
import com.example.auth.account.dto.WithdrawRequest;
import com.example.auth.account.service.AccountService;
import com.example.auth.global.common.ApiResponse;
import com.example.auth.global.security.CurrentAccount;
import com.example.auth.global.security.LoginAccount;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
 * <p>AU-05 가 만들고 AU-08·AU-09·AU-10 이 확장한다 (sp-docs/plan/phase1.md §2.3).
 *
 * <p>경로별 인가는 AU-04 의 {@code SecurityConfig} 가 선반영했다 — {@code POST /api/v1/accounts}
 * 는 무인증이다 (sp-docs/security.md §5.1).
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/accounts")
public class AccountController {

	private final AccountService accountService;

	/** 가입 1단계. 201 과 {@code {accountId, email}} (sp-docs/api-contract.md §9.1). */
	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public ApiResponse<AccountResponse> create(@Valid @RequestBody AccountCreateRequest request) {
		return ApiResponse.success(this.accountService.create(request));
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

}
