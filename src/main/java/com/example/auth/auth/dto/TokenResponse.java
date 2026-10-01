package com.example.auth.auth.dto;

/**
 * 로그인·재발급의 응답 본문. 정본: sp-docs/api-contract.md §9.2.
 *
 * <p>{@code accessTokenExpiresIn} 은 <b>초</b> 단위다 (30분 = 1800).
 */
public record TokenResponse(
		String grantType,
		String accessToken,
		String refreshToken,
		long accessTokenExpiresIn
) {

	/** {@code Authorization: Bearer {token}} 으로 쓴다 (sp-docs/security.md §1). */
	public static final String GRANT_TYPE_BEARER = "Bearer";

	public static TokenResponse bearer(String accessToken, String refreshToken, long accessTokenExpiresIn) {
		return new TokenResponse(GRANT_TYPE_BEARER, accessToken, refreshToken, accessTokenExpiresIn);
	}

}
