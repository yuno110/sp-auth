package com.example.auth.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import org.springframework.test.context.DynamicPropertyRegistry;

/**
 * 테스트용 RSA 키 페어.
 *
 * <p><b>개인키를 저장소에 두지 않기 위해 실행 시점에 만든다</b> (sp-docs/security.md §3).
 * 키 페어를 테스트 JVM 안에서 한 번 생성하고, 개인키를 PKCS#8 PEM 으로 임시 디렉터리에 써서
 * {@code jwt.private-key-location} 으로 넘긴다. sp-docs/tech-stack.md §4.2 의 {@code openssl
 * genpkey} 가 내놓는 것과 같은 형식이므로 PEM 파싱 경로까지 실제와 같이 돈다.
 *
 * <p>실제 개인키({@code ~/keys/sp/private.pem})는 테스트에서 쓰지 않는다. 테스트가 환경의
 * 비밀 값에 의존하면 다른 PC·CI 에서 돌지 않는다.
 *
 * <p>{@code @SpringBootTest} 로 전체 컨텍스트를 올리는 테스트는 {@link
 * #registerPrivateKeyLocation(DynamicPropertyRegistry)} 를 {@code @DynamicPropertySource} 에서
 * 호출한다. 호출하지 않으면 {@code application.yml} 의 {@code ${JWT_PRIVATE_KEY}} 가 해석되지
 * 않아 기동이 실패한다 — 그것이 의도된 동작이다.
 */
public final class TestRsaKeys {

	private static final KeyPair KEY_PAIR = generateKeyPair();
	private static final Path PRIVATE_KEY_FILE = writePrivateKeyPem(KEY_PAIR);

	private TestRsaKeys() {
	}

	/** {@code jwt.private-key-location} 에 넣을 Spring 리소스 경로. */
	public static String privateKeyLocation() {
		return "file:" + PRIVATE_KEY_FILE.toAbsolutePath();
	}

	/** 서명 검증에 쓸 공개키. 위 개인키와 같은 키 페어다. */
	public static RSAPublicKey publicKey() {
		return (RSAPublicKey) KEY_PAIR.getPublic();
	}

	public static void registerPrivateKeyLocation(DynamicPropertyRegistry registry) {
		registry.add("jwt.private-key-location", TestRsaKeys::privateKeyLocation);
	}

	private static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			// sp-docs/tech-stack.md §4.2 의 rsa_keygen_bits:2048 과 같다
			generator.initialize(2048);
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("RSA 키 페어를 만들 수 없다", e);
		}
	}

	private static Path writePrivateKeyPem(KeyPair keyPair) {
		String pem = "-----BEGIN PRIVATE KEY-----\n"
				+ Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(keyPair.getPrivate().getEncoded())
				+ "\n-----END PRIVATE KEY-----\n";
		try {
			// 저장소 밖(임시 디렉터리)에 둔다. 테스트 JVM 이 끝나면 지운다
			Path file = Files.createTempFile("sp-auth-test-signing-key", ".pem");
			file.toFile().deleteOnExit();
			Files.writeString(file, pem, StandardCharsets.US_ASCII);
			return file;
		} catch (IOException e) {
			throw new IllegalStateException("테스트 개인키 파일을 쓸 수 없다", e);
		}
	}

}
