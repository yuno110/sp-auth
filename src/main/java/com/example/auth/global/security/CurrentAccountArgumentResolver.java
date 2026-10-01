package com.example.auth.global.security;

import com.example.auth.account.entity.Role;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * {@link CurrentAccount} 파라미터를 검증된 JWT 에서 채운다.
 *
 * <p>등록은 {@code global/config/WebConfig} 가 한다.
 *
 * <p>인증이 없거나 principal 이 JWT 가 아니면 조용히 {@code null} 을 넣지 않고 예외를 던진다.
 * 기본값으로 메우면 인증 실패가 "익명 사용자"로 위장된다 (sp-docs/security.md §7).
 */
@Component
public class CurrentAccountArgumentResolver implements HandlerMethodArgumentResolver {

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return parameter.hasParameterAnnotation(CurrentAccount.class)
				&& LoginAccount.class.isAssignableFrom(parameter.getParameterType());
	}

	@Override
	public Object resolveArgument(
			MethodParameter parameter,
			ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest,
			WebDataBinderFactory binderFactory) {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
			throw new BusinessException(ErrorCode.UNAUTHORIZED);
		}
		return toLoginAccount(jwt);
	}

	private LoginAccount toLoginAccount(Jwt jwt) {
		// sub·role 은 api-contract.md §6 의 계약이다. 없거나 모르는 값이면 토큰이 잘못된 것이다
		try {
			return new LoginAccount(
					Long.valueOf(jwt.getSubject()),
					Role.valueOf(jwt.getClaimAsString(JwtTokenProvider.CLAIM_ROLE)));
		} catch (IllegalArgumentException | NullPointerException e) {
			throw new BusinessException(ErrorCode.INVALID_TOKEN);
		}
	}

}
