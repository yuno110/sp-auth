package com.example.auth.global.security;

import com.example.auth.account.entity.Role;
import com.example.auth.auth.dto.TokenResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

/**
 * 토큰 발급. <b>이 서비스가 발급하는 유일한 주체다</b> (sp-docs/security.md §2).
 *
 * <p>Claim 은 sp-docs/api-contract.md §6 이 정본이며 <b>세 서비스가 공유하는 계약</b>이다.
 * 임의로 claim 을 더하거나 빼지 않는다.
 *
 * <p><b>{@code nickname} claim 을 넣지 않는다.</b> 닉네임은 member 소유이고 auth 는 그 값을
 * 갖지 않는다. 넣으면 소유하지 않은 값을 서명하는 것이 된다 (sp-docs/api-contract.md §6,
 * sp-docs/adr/0012-auth-as-separate-service.md §3).
 *
 * <p>서명은 {@link JwtEncoder}({@code NimbusJwtEncoder}) 에 맡긴다. 직접 서명 로직을 만들지
 * 않는다 (sp-docs/tech-stack.md §2).
 */
@Component
public class JwtTokenProvider {

	/** sp-docs/api-contract.md §6 이 고정한 발급자 식별자다. */
	public static final String ISSUER = "auth-service";

	/** sp-docs/api-contract.md §6 의 권한 claim 이름. */
	public static final String CLAIM_ROLE = "role";

	private final JwtEncoder jwtEncoder;
	private final Duration accessTokenValidity;
	private final Duration refreshTokenValidity;

	public JwtTokenProvider(
			JwtEncoder jwtEncoder,
			@Value("${jwt.access-token-validity}") Duration accessTokenValidity,
			@Value("${jwt.refresh-token-validity}") Duration refreshTokenValidity) {
		this.jwtEncoder = jwtEncoder;
		this.accessTokenValidity = accessTokenValidity;
		this.refreshTokenValidity = refreshTokenValidity;
	}

	/**
	 * Access·Refresh 토큰을 함께 발급한다.
	 *
	 * @param accountId {@code account.id}. 전역 식별자이며 {@code sub} 가 된다
	 * @param role 권한. {@code role} claim 이 된다
	 */
	public TokenResponse issue(Long accountId, Role role) {
		// 두 토큰의 iat 를 같은 시각으로 둔다. 초 단위로 끊어 exp - iat 가 설정값과 정확히 같게 한다
		Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		return TokenResponse.bearer(
				sign(accountId, role, issuedAt, this.accessTokenValidity),
				sign(accountId, role, issuedAt, this.refreshTokenValidity),
				this.accessTokenValidity.toSeconds());
	}

	/** Refresh 토큰의 만료 시각. {@code refresh_token.expires_at} 에 저장한다. */
	public Duration getRefreshTokenValidity() {
		return this.refreshTokenValidity;
	}

	private String sign(Long accountId, Role role, Instant issuedAt, Duration validity) {
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.subject(String.valueOf(accountId))
				.claim(CLAIM_ROLE, role.name())
				.issuer(ISSUER)
				.issuedAt(issuedAt)
				.expiresAt(issuedAt.plus(validity))
				.build();

		// kid 는 JWK 에서 자동으로 header 에 실린다 (JwtConfig#jwtSigningKey)
		JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
		return this.jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
	}

}
