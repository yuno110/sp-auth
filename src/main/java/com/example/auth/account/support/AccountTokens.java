package com.example.auth.account.support;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * 링크 토큰의 생성과 해시 (sp-docs/requirements/member.md §11.1, sp-docs/domain-model.md §2.4).
 *
 * <p>토큰은 {@link SecureRandom} 32바이트를 base64url(패딩 없음)로 쓴 문자열이다. 메일의 링크에만 실린다.
 * 저장하는 것은 {@link #hash(String)} 의 값뿐이다 — DB 가 유출돼도 살아 있는 링크를 만들 수 없게 한다.
 * 토큰이 256비트 무작위라 소금·느린 해시가 필요 없다 (sp-docs/security.md §12).
 */
public final class AccountTokens {

	/** 토큰의 난수 바이트 수 (sp-docs/requirements/member.md §11.1). */
	static final int TOKEN_BYTES = 32;

	private static final SecureRandom RANDOM = new SecureRandom();

	private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

	private AccountTokens() {
	}

	/** 새 토큰. {@link SecureRandom} 32바이트의 base64url(패딩 없음)이다. */
	public static String generate() {
		byte[] bytes = new byte[TOKEN_BYTES];
		RANDOM.nextBytes(bytes);
		return BASE64URL.encodeToString(bytes);
	}

	/**
	 * 토큰 문자열(UTF-8)의 SHA-256 소문자 hex. {@code account_token.token_hash} 에 저장하는 값이다. 정본은 확인이
	 * 받은 문자열을 「같은 방식으로 해시해」 찾으라고 한다 (sp-docs/domain-model.md §2.4).
	 */
	public static String hash(String token) {
		try {
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			return HexFormat.of().formatHex(sha256.digest(token.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			// Java 플랫폼은 SHA-256 을 갖춰야 한다(MessageDigest 의 문서). 없으면 숨기지 않고 던진다
			throw new IllegalStateException("SHA-256 MessageDigest 가 없다", e);
		}
	}

}
