package com.example.auth.account.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.AccountToken;
import com.example.auth.account.entity.TokenPurpose;
import com.example.auth.global.config.JpaConfig;
import com.example.auth.support.MutableClock;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

/**
 * sp-docs/plan/phase2-auth-member.md §3 AU-12 의 "검증" 표 중 {@code account_token} 쪽이다. 정본은
 * sp-docs/domain-model.md §2.4, 규칙은 sp-docs/requirements/member.md §11.1.
 *
 * <p>애노테이션 둘은 sp-docs/conventions.md §9.3 의 조합이다 — {@code account_token} 의 FK 때문에
 * 계정을 저장하고, 계정은 감사 컬럼을 쓰므로 {@code JpaConfig} 가 필요하다.
 *
 * <p>시계는 {@link MutableClock} 을 직접 넘긴다. 만료는 시계를 움직여서 만든다.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(JpaConfig.class)
@ActiveProfiles("test")
class AccountTokenRepositoryTest {

	// 해시가 아니다. 커밋되는 파일에 BCrypt 모양 문자열을 두지 않는다
	// (sp-docs/requirements/member.md §10.2). 이 테스트는 계정을 FK 대상으로만 쓴다
	private static final String RAW_ENCODED_PASSWORD = "test-not-a-hash-encoded-password";

	/** 인증 토큰의 수명 (sp-docs/requirements/member.md §11.1). */
	private static final Duration VERIFICATION_LIFETIME = Duration.ofHours(24);

	private static final LocalDateTime ISSUED_AT = LocalDateTime.of(2026, 11, 13, 10, 0, 0);

	private static final SecureRandom RANDOM = new SecureRandom();

	@Autowired
	private TestEntityManager em;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private AccountTokenRepository accountTokenRepository;

	private final MutableClock clock = new MutableClock();

	@BeforeEach
	void setUp() {
		this.clock.set(ISSUED_AT);
	}

	@Test
	@DisplayName("사용 처리 — 쓰이지 않았고 만료 전이면 1행이고 used_at 이 채워진다")
	void 사용_처리_성공() {
		String hash = 발급(계정("consume-ok@example.com"), TokenPurpose.EMAIL_VERIFICATION);
		LocalDateTime usedAt = ISSUED_AT.plusMinutes(5);
		this.clock.set(usedAt);

		int updated = this.accountTokenRepository.consume(hash, TokenPurpose.EMAIL_VERIFICATION, this.clock);

		assertThat(updated).isEqualTo(1);
		assertThat(저장된(hash).getUsedAt()).isEqualTo(usedAt);
	}

	@Test
	@DisplayName("사용 처리 — 이미 쓴 토큰은 0행이고 처음 사용 시각이 남는다")
	void 사용_처리_이미_씀() {
		String hash = 발급(계정("consume-used@example.com"), TokenPurpose.EMAIL_VERIFICATION);
		LocalDateTime firstUse = ISSUED_AT.plusMinutes(5);
		this.clock.set(firstUse);
		assertThat(this.accountTokenRepository.consume(hash, TokenPurpose.EMAIL_VERIFICATION, this.clock))
				.as("첫 사용")
				.isEqualTo(1);
		this.clock.set(ISSUED_AT.plusMinutes(6));

		int updated = this.accountTokenRepository.consume(hash, TokenPurpose.EMAIL_VERIFICATION, this.clock);

		assertThat(updated).as("같은 토큰의 둘째 사용").isZero();
		assertThat(저장된(hash).getUsedAt()).isEqualTo(firstUse);
	}

	/**
	 * 만료 시각과 같은 순간에 만료다 — 문장의 조건이 {@code expires_at > now} 다
	 * (sp-docs/domain-model.md §2.4). 경계에 두어 {@code >=} 로 바뀌는 것도 잡는다.
	 */
	@Test
	@DisplayName("사용 처리 — 만료 시각이 되면 0행이다 (시계를 움직인다)")
	void 사용_처리_만료() {
		String hash = 발급(계정("consume-expired@example.com"), TokenPurpose.EMAIL_VERIFICATION);
		this.clock.set(ISSUED_AT.plus(VERIFICATION_LIFETIME));

		int updated = this.accountTokenRepository.consume(hash, TokenPurpose.EMAIL_VERIFICATION, this.clock);

		assertThat(updated).isZero();
		assertThat(저장된(hash).getUsedAt()).isNull();
	}

	@Test
	@DisplayName("사용 처리 — 목적이 다르면 0행이다")
	void 사용_처리_목적_다름() {
		String hash = 발급(계정("consume-purpose@example.com"), TokenPurpose.EMAIL_VERIFICATION);

		int updated = this.accountTokenRepository.consume(hash, TokenPurpose.PASSWORD_RESET, this.clock);

		assertThat(updated).isZero();
		assertThat(저장된(hash).getUsedAt()).isNull();
	}

	@Test
	@DisplayName("사용 처리 — 없는 해시는 0행이다")
	void 사용_처리_없는_해시() {
		// 테이블이 비어 있어서 0행인 것이 아니게, 다른 토큰 하나를 둔다
		String issued = 발급(계정("consume-missing@example.com"), TokenPurpose.EMAIL_VERIFICATION);

		int updated = this.accountTokenRepository.consume(새_토큰_해시(), TokenPurpose.EMAIL_VERIFICATION, this.clock);

		assertThat(updated).isZero();
		assertThat(저장된(issued).getUsedAt()).isNull();
	}

	/**
	 * 같은 계정·같은 목적의 행이 둘인 것은 겹친 발급이 남길 수 있는 상태다
	 * (sp-docs/requirements/member.md §11.1). 둘 다 지워지는지 본다.
	 */
	@Test
	@DisplayName("같은 계정·목적의 행 지우기 — 그 계정·목적의 행만 지워진다")
	void 같은_계정_목적의_행만_지운다() {
		Long accountId = 계정("delete-target@example.com");
		Long otherAccountId = 계정("delete-other@example.com");
		String target1 = 발급(accountId, TokenPurpose.EMAIL_VERIFICATION);
		String target2 = 발급(accountId, TokenPurpose.EMAIL_VERIFICATION);
		String otherPurpose = 발급(accountId, TokenPurpose.PASSWORD_RESET);
		String otherAccount = 발급(otherAccountId, TokenPurpose.EMAIL_VERIFICATION);

		int deleted = this.accountTokenRepository.deleteByAccountIdAndPurpose(
				accountId, TokenPurpose.EMAIL_VERIFICATION);

		assertThat(deleted).isEqualTo(2);
		assertThat(this.accountTokenRepository.findByTokenHash(target1)).isEmpty();
		assertThat(this.accountTokenRepository.findByTokenHash(target2)).isEmpty();
		assertThat(this.accountTokenRepository.findByTokenHash(otherPurpose))
				.as("같은 계정의 다른 목적")
				.isPresent();
		assertThat(this.accountTokenRepository.findByTokenHash(otherAccount))
				.as("다른 계정의 같은 목적")
				.isPresent();
	}

	/**
	 * 길이 제약이 의미를 갖는 컬럼은 실제 최대 길이로 본다 (sp-docs/conventions.md §9.2). 해시는
	 * 정본의 생성 규칙으로 만들고, 목적은 열거 값 중 이름이 가장 긴 것을 고른다 — 열거 값이 늘어도
	 * 이 테스트가 따라간다.
	 */
	@Test
	@DisplayName("token_hash 64자와 이름이 가장 긴 purpose 가 저장되고 purpose 는 이름으로 저장된다")
	void 최대_길이가_저장된다() {
		TokenPurpose longest = Arrays.stream(TokenPurpose.values())
				.max(Comparator.comparingInt(p -> p.name().length()))
				.orElseThrow();
		Long accountId = 계정("max-length@example.com");
		String hash = 새_토큰_해시();
		assertThat(hash).as("픽스처 — SHA-256 hex 는 64자다").hasSize(64);

		Long id = this.accountTokenRepository.saveAndFlush(
				AccountToken.issue(accountId, longest, hash, VERIFICATION_LIFETIME, this.clock)).getId();
		this.em.clear();

		Object[] stored = (Object[]) this.em.getEntityManager()
				.createNativeQuery("select token_hash, purpose from account_token where id = :id")
				.setParameter("id", id)
				.getSingleResult();
		assertThat(stored[0]).isEqualTo(hash);
		assertThat(stored[1]).as("ORDINAL 이 아니라 이름이다").isEqualTo(longest.name());
	}

	/**
	 * 컬럼이 {@code DATETIME} 이라 MySQL 은 소수부를 반올림하고 H2 는 남긴다
	 * (sp-docs/domain-model.md §1.1). 쓰는 쪽이 초로 자르지 않으면 이 H2 테스트에서 소수부가 남는다.
	 */
	@Test
	@DisplayName("소수부가 있는 시계로 쓴 created_at·expires_at·used_at 은 저장값에 소수부가 없다")
	void 시각은_초로_잘려_저장된다() {
		Long accountId = 계정("fraction@example.com");
		this.clock.set(ISSUED_AT.withNano(700_000_000));
		String hash = 발급(accountId, TokenPurpose.EMAIL_VERIFICATION);
		this.clock.set(ISSUED_AT.plusMinutes(1).withNano(300_000_000));

		assertThat(this.accountTokenRepository.consume(hash, TokenPurpose.EMAIL_VERIFICATION, this.clock))
				.isEqualTo(1);

		AccountToken stored = 저장된(hash);
		assertThat(stored.getCreatedAt()).isEqualTo(ISSUED_AT);
		assertThat(stored.getExpiresAt()).isEqualTo(ISSUED_AT.plus(VERIFICATION_LIFETIME));
		assertThat(stored.getUsedAt()).isEqualTo(ISSUED_AT.plusMinutes(1));
		assertThat(List.of(stored.getCreatedAt(), stored.getExpiresAt(), stored.getUsedAt()))
				.allSatisfy(time -> assertThat(time.getNano()).isZero());
	}

	private Long 계정(String email) {
		return this.accountRepository.saveAndFlush(Account.builder()
				.email(email)
				.password(RAW_ENCODED_PASSWORD)
				.build()).getId();
	}

	/** 지금 시계로 토큰 하나를 발급해 저장하고 그 해시를 돌려준다. */
	private String 발급(Long accountId, TokenPurpose purpose) {
		String hash = 새_토큰_해시();
		this.accountTokenRepository.saveAndFlush(
				AccountToken.issue(accountId, purpose, hash, VERIFICATION_LIFETIME, this.clock));
		this.em.clear();
		return hash;
	}

	/** 영속성 컨텍스트를 비우고 DB 에서 다시 읽는다 — 엔터티 값이 아니라 저장값을 본다. */
	private AccountToken 저장된(String hash) {
		this.em.clear();
		return this.accountTokenRepository.findByTokenHash(hash).orElseThrow();
	}

	/**
	 * 정본의 생성 규칙으로 토큰을 만들고 그 해시를 돌려준다 — 32바이트 난수를 base64url(패딩 없음)로
	 * 쓴 문자열의 UTF-8 SHA-256 소문자 hex (sp-docs/requirements/member.md §11.1,
	 * sp-docs/domain-model.md §2.4). 난수라 부를 때마다 값이 다르다.
	 */
	private static String 새_토큰_해시() {
		byte[] raw = new byte[32];
		RANDOM.nextBytes(raw);
		String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

}
