package com.example.auth.account.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * 비밀번호 변경 요청. 정본: sp-docs/api-contract.md §2.2 (v10), 검증 규칙은
 * sp-docs/requirements/member.md §2.
 *
 * <p><b>필드는 {@code currentPassword}·{@code newPassword} 둘이다</b> (§2.2).
 *
 * <p><b>두 필드의 검증이 비대칭이다. 의도다.</b> {@code currentPassword} 는 자격증명 필드이고
 * {@code newPassword} 는 생성되는 값이다.
 *
 * <table border="1">
 * <caption>sp-docs/api-contract.md §2.2 의 검증 표</caption>
 * <tr><th>필드</th><th>검증</th></tr>
 * <tr><td>{@code currentPassword}</td><td><b>{@code @NotBlank} 만</b> 붙인다.
 * {@code @Pattern} 은 걸지 않는다</td></tr>
 * <tr><td>{@code newPassword}</td><td>sp-docs/requirements/member.md §2 의 비밀번호 규칙.
 * 위반은 400 {@code C001}</td></tr>
 * </table>
 *
 * <p><b>자격증명 필드에서 금지되는 것은 형식 검증이고, 빈 값 검사는 아니다</b> (§2.2 v10).
 * 둘이 갈리는 이유가 다르다.
 *
 * <ul>
 * <li><b>{@code @Pattern} 금지</b> — 비밀번호 정책이 바뀌면 옛 규칙으로 만든 <b>올바른</b>
 * 비밀번호가 형식 검증에 거부된다. 그러면 <b>비밀번호를 바꾸려는 사용자가 바로 그 화면에서
 * 막힌다</b> — 정책을 갱신하려는 바로 그 요청이 옛 비밀번호를 담고 있기 때문이다
 * (sp-docs/requirements/member.md §2.1)
 * <li><b>{@code @NotBlank} 요구</b> — 빈 값은 <b>어떤 정책에서도</b> 올바른 비밀번호가 아니므로
 * 잠글 사용자가 없다. 누락은 형식 문제가 아니라 "필드를 보내지 않았다"이고, 저장된 비밀번호에
 * 대해 아무것도 드러내지 않는다. 그래서 400 {@code C001} 이고 {@code fieldErrors} 에
 * {@code currentPassword} 가 담긴다 — {@code AU004} 의 메시지("현재 비밀번호가 일치하지
 * 않습니다")는 <b>아무것도 보내지 않은 요청에는 거짓이다</b>
 * </ul>
 *
 * <p>값이 틀린 경우(형식 위반이든 아니든)는 400 {@code AU004} 이고 {@code AccountService} 가
 * 판정한다. <b>형식으로 가르지 않는다.</b>
 *
 * <p>{@code newPassword} 의 제약은 {@link AccountCreateRequest} 의 상수를 그대로 쓴다 — 같은
 * 규칙(sp-docs/requirements/member.md §2)이므로 두 군데 적지 않는다.
 */
public record PasswordChangeRequest(

		@NotBlank(message = CURRENT_PASSWORD_MESSAGE)
		String currentPassword,

		@NotBlank(message = AccountCreateRequest.PASSWORD_MESSAGE)
		@Pattern(regexp = AccountCreateRequest.PASSWORD_PATTERN,
				message = AccountCreateRequest.PASSWORD_MESSAGE)
		String newPassword) {

	/**
	 * <b>존재 메시지다. 정책 메시지가 아니다</b> (sp-docs/api-contract.md §2.2 v10).
	 *
	 * <p>{@link AccountCreateRequest} 의 비밀번호 메시지를 쓰지 않는다 — 그것은 "8~20자의
	 * 영문, 숫자, 특수문자 조합"이라는 <b>정책 설명</b>이고, 여기서 실패한 것은 정책이 아니라
	 * 값을 보내지 않은 것이다. 정책 메시지를 돌려주면 사용자가 <b>자기 비밀번호의 형식이 틀렸다고
	 * 읽는다.</b>
	 */
	static final String CURRENT_PASSWORD_MESSAGE = "현재 비밀번호를 입력해주세요.";

}
