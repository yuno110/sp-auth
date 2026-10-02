package com.example.auth.account.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * 계정 생성 요청 (가입 1단계). 정본: sp-docs/api-contract.md §9.1, 검증 규칙은
 * sp-docs/requirements/member.md §2.
 *
 * <p><b>필드는 {@code email}·{@code password} 둘뿐이다.</b> 닉네임은 member 소유이므로 받지
 * 않는다 (sp-docs/adr/0012-auth-as-separate-service.md). 본문에 {@code nickname} 이 와도 Boot 의
 * 기본 Jackson 설정({@code FAIL_ON_UNKNOWN_PROPERTIES=false})이 무시하므로 저장될 경로가 없다 —
 * {@code account} 테이블에 그 컬럼 자체가 없다 (sp-docs/domain-model.md §2.1).
 *
 * <p>검증 실패는 {@code C001}(400)이 되고 필드별 메시지가 {@code fieldErrors} 에 담긴다
 * (sp-docs/requirements/member.md §2, sp-docs/api-contract.md §7).
 */
public record AccountCreateRequest(

		@NotBlank(message = EMAIL_MESSAGE)
		@Email(message = EMAIL_MESSAGE)
		@Size(max = EMAIL_MAX_LENGTH, message = EMAIL_MESSAGE)
		String email,

		@NotBlank(message = PASSWORD_MESSAGE)
		@Pattern(regexp = PASSWORD_PATTERN, message = PASSWORD_MESSAGE)
		String password) {

	/**
	 * sp-docs/requirements/member.md §2. 항목당 메시지가 하나이므로 세 제약이 같은 값을 쓴다.
	 *
	 * <p><b>{@code public} 인 이유</b> — {@code GET /accounts/check-email} 의 {@code email}
	 * 파라미터가 <b>생성과 같은 규칙</b>을 써야 한다 (sp-docs/api-contract.md §2.3). 규칙을 두 군데
	 * 적지 않기 위해 {@code AccountController} 가 이 상수를 참조한다.
	 */
	public static final String EMAIL_MESSAGE = "올바른 이메일 형식이 아닙니다.";

	/** 이메일 최대 길이 (sp-docs/requirements/member.md §2). {@code account.email} 컬럼과 같다. */
	public static final int EMAIL_MAX_LENGTH = 100;

	// 비밀번호 상수는 package-private 다. 이메일 쪽만 public 인 것은 비대칭이지만,
	// 비밀번호를 파라미터로 받는 엔드포인트가 없어 밖에서 참조할 곳이 없다 (AGENTS.md 불변식 2).
	// 그런 엔드포인트가 생기면 그때 올린다
	static final String PASSWORD_MESSAGE = "비밀번호는 8~20자의 영문, 숫자, 특수문자 조합이어야 합니다.";

	/**
	 * 8~20자, 영문·숫자·특수문자 각 1자 이상 (sp-docs/requirements/member.md §2 §2.1).
	 *
	 * <p>특수문자 집합은 §2.1 이 고정한 ASCII 구두점 32자다. 문자 하나하나를 적으면
	 * {@code "}·{@code \}·{@code ]} 이스케이프가 섞여 정본과 대조하기 어려우므로 코드포인트
	 * 범위로 적는다 — 넷을 합치면 §2.1 의 목록과 정확히 같다.
	 *
	 * <pre>
	 * \x21-\x2F  ! " # $ % &amp; ' ( ) * + , - . /
	 * \x3A-\x40  : ; &lt; = &gt; ? {@literal @}
	 * \x5B-\x60  [ \ ] ^ _ `
	 * \x7B-\x7E  { | } ~
	 * </pre>
	 *
	 * <p>전체 문자는 {@code \x21-\x7E}(ASCII 출력 가능)로 제한하므로 <b>공백(0x20)과 한글이
	 * 들어가면 실패한다</b> — {@code 비밀번호1234} 가 특수문자 조건을 충족한 것으로 통과하지
	 * 않는다 (§2.1).
	 */
	static final String PASSWORD_PATTERN = "^(?=.*[A-Za-z])(?=.*[0-9])"
			+ "(?=.*[\\x21-\\x2F\\x3A-\\x40\\x5B-\\x60\\x7B-\\x7E])[\\x21-\\x7E]{8,20}$";

}
