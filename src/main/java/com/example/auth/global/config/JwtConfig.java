package com.example.auth.global.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.StringUtils;

/**
 * 서명 키 로딩. <b>이 서비스만 개인키를 갖는다</b> (sp-docs/security.md §2 §3).
 *
 * <p>개인키는 저장소 밖에 두고 {@code jwt.private-key-location} 으로 경로만 주입받는다.
 * <b>기본값을 두지 않는다 — 없으면 기동이 실패한다</b> (sp-docs/security.md §3,
 * sp-docs/tech-stack.md §4.3). 실패를 조용히 통과시키지 않기 위해서다 (sp-docs/security.md §7).
 *
 * <p>서명·검증기는 Spring Security 표준을 쓴다. 직접 만들지 않는다
 * (sp-docs/tech-stack.md §2, sp-docs/conventions.md §7.2).
 */
@Configuration
public class JwtConfig {

	/**
	 * 서명에 쓸 JWK. header 의 {@code kid} 가 여기서 나온다.
	 *
	 * <p><b>{@code kid} 값은 공개키 thumbprint(RFC 7638)다.</b> 정본(sp-docs/security.md §3,
	 * sp-docs/api-contract.md §6)은 {@code kid} 의 <i>포함</i>만 정하고 값의 생성 방식을 정하지
	 * 않았다. thumbprint 는 키에서 계산되는 값이라 임의로 정한 상수가 아니고, 키를 재생성하면
	 * 자동으로 바뀌므로 §3 의 "키 회전" 용도와 맞는다. 1차에서 검증 측(member·board)은
	 * 공개키 하나를 설정으로 받아 {@code kid} 를 보지 않으므로(sp-docs/tech-stack.md §2.1)
	 * 이 값은 서비스 간 계약값이 아니다.
	 */
	@Bean
	public RSAKey jwtSigningKey(
			@Value("${jwt.private-key-location}") String privateKeyLocation,
			ResourceLoader resourceLoader) {

		if (!StringUtils.hasText(privateKeyLocation)) {
			throw new IllegalStateException(
					"jwt.private-key-location 이 비어 있다. 개인키는 기본값 없이 외부에서 주입한다 "
							+ "(sp-docs/security.md §3).");
		}

		Resource resource = resourceLoader.getResource(privateKeyLocation);
		if (!resource.exists()) {
			// 경로를 메시지에 남긴다. 키 내용은 남기지 않는다 (sp-docs/conventions.md §8)
			throw new IllegalStateException(
					"개인키를 찾을 수 없다: " + privateKeyLocation);
		}

		RSAPrivateKey privateKey = readPkcs8PrivateKey(resource);
		try {
			return new RSAKey.Builder(toPublicKey(privateKey))
					.privateKey(privateKey)
					.keyIDFromThumbprint()
					.build();
		} catch (JOSEException e) {
			throw new IllegalStateException("개인키로 JWK 를 만들 수 없다: " + privateKeyLocation, e);
		}
	}

	@Bean
	public JwtEncoder jwtEncoder(RSAKey jwtSigningKey) {
		JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwtSigningKey));
		return new NimbusJwtEncoder(jwkSource);
	}

	/**
	 * 자기가 발급한 토큰을 검증한다 (sp-docs/tech-stack.md §3.2).
	 *
	 * <p>개인키에서 뽑은 공개키로만 검증하므로 다른 발급자의 토큰은 통과하지 못한다.
	 * {@code iss} 는 sp-docs/api-contract.md §6 이 {@code auth-service} 로 고정한다.
	 */
	@Bean
	public JwtDecoder jwtDecoder(RSAKey jwtSigningKey) {
		try {
			return NimbusJwtDecoder.withPublicKey(jwtSigningKey.toRSAPublicKey())
					.signatureAlgorithm(SignatureAlgorithm.RS256)
					.build();
		} catch (JOSEException e) {
			throw new IllegalStateException("JWK 에서 공개키를 꺼낼 수 없다", e);
		}
	}

	private RSAPrivateKey readPkcs8PrivateKey(Resource resource) {
		try (InputStream in = resource.getInputStream()) {
			return RsaKeyConverters.pkcs8().convert(in);
		} catch (IOException e) {
			throw new IllegalStateException("개인키를 읽을 수 없다: " + resource.getDescription(), e);
		}
	}

	/**
	 * 개인키에서 공개키를 복원한다.
	 *
	 * <p>PKCS#8 RSA 개인키는 modulus 와 publicExponent 를 함께 담으므로 공개키 파일이 필요 없다.
	 * auth 는 공개키 파일을 두지 않는다 — 배포 대상은 member·board 다 (sp-docs/security.md §3).
	 */
	private RSAPublicKey toPublicKey(RSAPrivateKey privateKey) {
		if (!(privateKey instanceof RSAPrivateCrtKey crtKey)) {
			throw new IllegalStateException(
					"RSA CRT 개인키가 아니라 공개키를 복원할 수 없다. 키 생성은 "
							+ "sp-docs/tech-stack.md §4.2 절차를 따른다.");
		}
		try {
			return (RSAPublicKey) KeyFactory.getInstance("RSA")
					.generatePublic(new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent()));
		} catch (Exception e) {
			throw new IllegalStateException("개인키에서 공개키를 복원할 수 없다", e);
		}
	}

}
