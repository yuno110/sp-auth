package com.example.auth.support;

import com.example.auth.account.entity.Role;
import com.example.auth.global.security.JwtTokenProvider;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

/**
 * 발급 시각을 지정해 서명한 토큰 픽스처. <b>조립한 값이다</b>
 * (sp-docs/conventions.md §9.2 의 예외).
 *
 * <p><b>왜 발급 경로({@code JwtTokenProvider.issue})를 쓸 수 없는가</b> — Claim 에 {@code jti}
 * 가 없고 {@code iat} 가 초 단위이며 {@code exp} 가 {@code iat} 에서 유도되므로, <b>같은 계정이
 * 같은 초에 두 번 발급받으면 토큰 문자열이 완전히 같다</b>
 * (sp-docs/requirements/member.md §6.2). 그래서 회전 전후를 비교하는 테스트와 만료된 토큰이
 * 필요한 테스트는 발급 경로로 만들 수 없다. <b>{@code Thread.sleep} 으로 우회하지 않는다</b> —
 * 느려지고 초 경계에 걸리면 여전히 같아진다 (sp-docs/conventions.md §9.2).
 *
 * <p><b>조립하는 것은 {@code iat} 하나다.</b> 서명은 애플리케이션의 {@link JwtEncoder} 빈
 * (= 실제 개인키)으로 하고 claim 집합도 {@code JwtTokenProvider} 와 같게 둔다
 * (sp-docs/api-contract.md §6). 그러지 않으면 "서명이 옳은 옛 토큰"이 아니라 그냥 잘못된
 * 토큰이 되어, 검증하려던 경로(저장값 대조)에 닿지 못하고 서명 오류로 떨어진다.
 */
public final class TestTokens {

	private TestTokens() {
	}

	/**
	 * {@code issuedAt} 에 발급된 것으로 서명한 토큰.
	 *
	 * @param validity {@code exp - iat}. Refresh 는 14일, Access 는 30분이다
	 *         (sp-docs/security.md §1)
	 */
	public static String signed(
			JwtEncoder jwtEncoder, Long accountId, Role role, Instant issuedAt, Duration validity) {

		// 발급 경로와 같이 초 단위로 끊는다 (JwtTokenProvider#issue)
		Instant iat = issuedAt.truncatedTo(ChronoUnit.SECONDS);
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.subject(String.valueOf(accountId))
				.claim(JwtTokenProvider.CLAIM_ROLE, role.name())
				.issuer(JwtTokenProvider.ISSUER)
				.issuedAt(iat)
				.expiresAt(iat.plus(validity))
				.build();

		JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
		return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

	/**
	 * 서명 부분의 첫 글자를 다른 base64url 문자로 바꾼다.
	 *
	 * <p>형식·header·payload 는 그대로이므로 디코더가 <b>서명 검증까지 가서</b> 실패한다 —
	 * 그래야 {@code A002} 가 "형식이 깨졌다"가 아니라 "서명이 잘못됐다"를 보는 것이 된다
	 * (sp-docs/plan/phase1.md §4 AU-07).
	 */
	public static String tamperSignature(String token) {
		int signatureStart = token.lastIndexOf('.') + 1;
		char original = token.charAt(signatureStart);
		char replacement = (original == 'A') ? 'B' : 'A';
		return token.substring(0, signatureStart) + replacement + token.substring(signatureStart + 1);
	}

}
