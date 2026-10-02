package com.example.auth.account.controller;

import com.example.auth.account.dto.AccountCreateRequest;
import com.example.auth.account.dto.AccountResponse;
import com.example.auth.account.dto.CheckResponse;
import com.example.auth.account.service.AccountService;
import com.example.auth.global.common.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
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

}
