package com.example.auth.global.security;

import com.example.auth.account.entity.Role;
import com.example.auth.auth.dto.TokenResponse;
import com.example.auth.global.error.BusinessException;
import com.example.auth.global.error.ErrorCode;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.stereotype.Component;

/**
 * 토큰 발급과 검증. <b>이 서비스가 발급하는 유일한 주체다</b> (sp-docs/security.md §2).
 *
 * <p>Claim 은 sp-docs/api-contract.md §6 이 정본이며 <b>세 서비스가 공유하는 계약</b>이다.
 * 임의로 claim 을 더하거나 빼지 않는다.
 *
 * <p><b>{@code nickname} claim 을 넣지 않는다.</b> 닉네임은 member 소유이고 auth 는 그 값을
 * 갖지 않는다. 넣으면 소유하지 않은 값을 서명하는 것이 된다 (sp-docs/api-contract.md §6,
 * sp-docs/adr/0012-auth-as-separate-service.md §3).
 *
 * <p>서명은 {@link JwtEncoder}({@code NimbusJwtEncoder}) 에, 검증은 {@link JwtDecoder}
 * ({@code NimbusJwtDecoder}) 에 맡긴다. 직접 서명·검증 로직을 만들지 않는다
 * (sp-docs/tech-stack.md §2, sp-docs/conventions.md §7.2).
 *
 * <p><b>검증 실패를 에러 코드로 가르는 판정이 여기 하나뿐이다</b> ({@link #failureCode}).
 * 필터 단계({@code SecurityErrorResponder} — Access Token)와 재발급 경로
 * ({@code AuthService} — Refresh Token)가 같은 판정을 쓴다. 두 군데에 적으면 언젠가 갈린다.
 */
@Component
public class JwtTokenProvider {

	/** sp-docs/api-contract.md §6 이 고정한 발급자 식별자다. */
	public static final String ISSUER = "auth-service";

	/** sp-docs/api-contract.md §6 의 권한 claim 이름. */
	public static final String CLAIM_ROLE = "role";

	private final JwtEncoder jwtEncoder;
	private final JwtDecoder jwtDecoder;
	private final Duration accessTokenValidity;
	private final Duration refreshTokenValidity;

	public JwtTokenProvider(
			JwtEncoder jwtEncoder,
			JwtDecoder jwtDecoder,
			@Value("${jwt.access-token-validity}") Duration accessTokenValidity,
			@Value("${jwt.refresh-token-validity}") Duration refreshTokenValidity) {
		this.jwtEncoder = jwtEncoder;
		this.jwtDecoder = jwtDecoder;
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

	/**
	 * 제시된 토큰의 <b>서명과 만료</b>를 검증하고 {@code sub}(= {@code account.id}) 를 꺼낸다
	 * (sp-docs/security.md §4 의 "서명·만료 검증").
	 *
	 * <p>재발급이 쓴다. Refresh Token 은 {@code Authorization} 헤더가 아니라 본문으로 오므로
	 * 필터 체인이 보지 않는다 — 검증 지점이 여기다.
	 *
	 * <p><b>만료 판정의 출처는 토큰의 {@code exp} claim 이다.</b> {@code refresh_token.expires_at}
	 * 컬럼은 같은 발급에서 유도된 사본이고, 정본이 재발급 흐름에 적은 검증은 "서명·만료 검증 +
	 * 저장값 일치 확인"이므로 만료는 토큰이, 일치는 저장값이 판정한다 (sp-docs/security.md §4).
	 *
	 * @throws BusinessException 서명·형식 오류면 {@code A002}, 만료면 {@code A003}
	 *         (sp-docs/api-contract.md §8.1)
	 */
	public Long verifiedAccountId(String token) {
		Jwt jwt;
		try {
			jwt = this.jwtDecoder.decode(token);
		} catch (JwtException e) {
			throw new BusinessException(failureCode(e));
		}

		// sub 은 api-contract.md §6 의 계약이다. 없거나 숫자가 아니면 토큰이 잘못된 것이다.
		// 가드가 없으면 NumberFormatException 이 500 C005 로 새어 나간다
		try {
			return Long.valueOf(jwt.getSubject());
		} catch (IllegalArgumentException | NullPointerException e) {
			throw new BusinessException(ErrorCode.INVALID_TOKEN);
		}
	}

	/**
	 * 인증 실패를 {@code A001}·{@code A002}·{@code A003} 으로 가른다
	 * (sp-docs/api-contract.md §8.1). 필터 단계와 재발급 경로가 공유하는 판정이다.
	 *
	 * <p><b>예외 타입으로 가른다. 메시지 문자열을 보지 않는다.</b> 근거는
	 * {@code NimbusJwtDecoder#decode} 의 순서다 — 서명 검증이 claim 검증보다 먼저이고,
	 * 서명·형식 오류는 {@code BadJwtException}, 그것을 통과한 뒤의 claim 검증 실패는
	 * {@link JwtValidationException}(= {@code BadJwtException} 의 하위)이다. 따라서
	 * {@code JwtValidationException} 은 <b>서명은 옳고 claim 이 틀린</b> 경우만이다.
	 *
	 * <p>그 claim 검증기는 {@code JwtValidators.createDefault()} 의 둘이다 —
	 * {@code JwtTimestampValidator}(측정: 기본 clock skew 60초)와
	 * {@code X509CertificateThumbprintValidator}(이 서비스의 토큰에는 {@code cnf} claim 이
	 * 없으므로 항상 통과). {@code iss} 검증기는 {@code JwtConfig} 가 붙이지 않았고 {@code nbf}
	 * 는 발급하지 않는다. 그래서 여기서 {@code JwtValidationException} 은 <b>만료</b>다.
	 * {@code JwtConfig} 가 claim 검증기를 더하면 이 전제가 깨지므로 그때 함께 고친다.
	 *
	 * <p>필터 단계의 예외는 {@code InvalidBearerTokenException} 으로 한 겹 감싸여 오므로
	 * (원인은 보존된다) 원인 사슬을 따라간다. {@code JwtException} 이 사슬에 없으면 <b>토큰이
	 * 아예 없는 것</b>이고 {@code A001} 이다.
	 */
	public static ErrorCode failureCode(Throwable failure) {
		for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
			// 하위 타입을 먼저 본다. JwtValidationException 은 JwtException 이기도 하다
			if (cause instanceof JwtValidationException) {
				return ErrorCode.EXPIRED_TOKEN;
			}
			if (cause instanceof JwtException) {
				return ErrorCode.INVALID_TOKEN;
			}
		}
		return ErrorCode.UNAUTHORIZED;
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
