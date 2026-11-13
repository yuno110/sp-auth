package com.example.auth.account.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 링크 토큰의 모양과 해시 (sp-docs/requirements/member.md §11.1, sp-docs/domain-model.md §2.4).
 */
class AccountTokensTest {

	@Test
	@DisplayName("토큰은 32바이트를 base64url(패딩 없음)로 쓴 43자다")
	void 토큰은_32바이트의_base64url_이다() {
		String token = AccountTokens.generate();

		assertThat(token).hasSize(43).matches("[A-Za-z0-9_-]+");
		assertThat(Base64.getUrlDecoder().decode(token)).hasSize(32);
		assertThat(AccountTokens.generate()).as("호출마다 새 난수다").isNotEqualTo(token);
	}

	/** FIPS 180-2 의 SHA-256 예제 「abc」 다. 소문자 hex 여야 저장값과 같다. */
	@Test
	@DisplayName("해시는 SHA-256 의 소문자 hex 64자다")
	void 해시는_SHA_256_소문자_hex_다() {
		assertThat(AccountTokens.hash("abc"))
				.isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	}

	/**
	 * 확인은 받은 문자열을 형식 검사 없이 해시한다 (sp-docs/api-contract.md §2.4). ASCII 밖의 문자에서
	 * 문자 집합이 갈린다 — UTF-8 이 아니면 이 단언이 깨진다.
	 */
	@Test
	@DisplayName("해시는 문자열의 UTF-8 바이트를 해시한다")
	void 해시는_UTF_8_바이트를_해시한다() throws NoSuchAlgorithmException {
		String value = "토큰-é";
		String expected = HexFormat.of().formatHex(
				MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));

		assertThat(AccountTokens.hash(value)).isEqualTo(expected);
	}

}
