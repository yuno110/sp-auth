package com.example.auth.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.account.entity.Account;
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.global.config.JpaConfig;
import java.time.LocalDateTime;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

/**
 * sp-docs/plan/phase1.md §4 AU-03 의 "검증" 표 중 refresh_token 쪽을 테스트로 옮긴 것이다.
 *
 * <p><b>핵심은 {@code 삭제된_행에_회전하면_0행이고_되살아나지_않는다} 다.</b> 재현 순서는
 * sp-docs/requirements/member.md §6 에 있다. 회전이 조건부 UPDATE 가 아니라
 * "조회 → 삭제 → INSERT" 면 이 테스트가 깨진다 — 탈퇴로 지운 행이 되살아나 탈퇴한 계정이
 * 14일간 토큰을 갱신할 수 있게 된다.
 *
 * <p>{@code replace = NONE} 이 필요한 이유는 sp-docs/tech-stack.md §5.2 에 있다.
 *
 * <p>{@code refresh_token} 에는 감사 컬럼이 없지만, FK 대상인 {@code account} 를 만들려면
 * {@code @EnableJpaAuditing} 이 필요하다. {@code @DataJpaTest} 는 {@code @Configuration} 을
 * 스캔하지 않으므로 {@code JpaConfig} 를 직접 올린다.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(JpaConfig.class)
@ActiveProfiles("test")
class RefreshTokenRepositoryTest {

	private static final String OLD_TOKEN = "old.refresh.token";
	private static final String NEW_TOKEN = "new.refresh.token";
	private static final LocalDateTime OLD_EXPIRES_AT = LocalDateTime.of(2026, 10, 13, 9, 0, 0);
	private static final LocalDateTime NEW_EXPIRES_AT = LocalDateTime.of(2026, 10, 20, 9, 0, 0);

	@Autowired
	private TestEntityManager em;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Test
	@DisplayName("저장 후 조회하면 모든 필드가 일치한다")
	void 저장_후_조회() {
		Long accountId = persistAccount("store@example.com");

		RefreshToken saved = refreshTokenRepository.saveAndFlush(refreshToken(accountId, OLD_TOKEN, OLD_EXPIRES_AT));
		em.clear();

		RefreshToken found = refreshTokenRepository.findById(saved.getId()).orElseThrow();
		assertThat(found.getAccountId()).isEqualTo(accountId);
		assertThat(found.getToken()).isEqualTo(OLD_TOKEN);
		assertThat(found.getExpiresAt()).isEqualTo(OLD_EXPIRES_AT);
	}

	@Test
	@DisplayName("같은 account_id 로 두 행을 저장하면 DataIntegrityViolationException 이 난다")
	void account_id_중복() {
		Long accountId = persistAccount("one-row@example.com");
		refreshTokenRepository.saveAndFlush(refreshToken(accountId, OLD_TOKEN, OLD_EXPIRES_AT));
		RefreshToken second = refreshToken(accountId, NEW_TOKEN, NEW_EXPIRES_AT);

		assertThatThrownBy(() -> refreshTokenRepository.saveAndFlush(second))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("같은 token 으로 두 행을 저장하면 DataIntegrityViolationException 이 난다")
	void token_중복() {
		Long first = persistAccount("token-a@example.com");
		Long second = persistAccount("token-b@example.com");
		refreshTokenRepository.saveAndFlush(refreshToken(first, OLD_TOKEN, OLD_EXPIRES_AT));
		RefreshToken sameToken = refreshToken(second, OLD_TOKEN, NEW_EXPIRES_AT);

		assertThatThrownBy(() -> refreshTokenRepository.saveAndFlush(sameToken))
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	@Test
	@DisplayName("저장값과 일치하는 토큰으로 회전하면 1행이 갱신된다")
	void 정상_회전() {
		Long accountId = persistAccount("rotate@example.com");
		refreshTokenRepository.saveAndFlush(refreshToken(accountId, OLD_TOKEN, OLD_EXPIRES_AT));

		int affected = refreshTokenRepository.rotate(accountId, OLD_TOKEN, NEW_TOKEN, NEW_EXPIRES_AT);

		assertThat(affected).isOne();
		RefreshToken found = refreshTokenRepository.findByAccountId(accountId).orElseThrow();
		assertThat(found.getToken()).isEqualTo(NEW_TOKEN);
		assertThat(found.getExpiresAt()).isEqualTo(NEW_EXPIRES_AT);
	}

	@Test
	@DisplayName("이미 삭제된 행에 회전을 시도하면 0행이고 행이 되살아나지 않는다")
	void 삭제된_행에_회전하면_0행이고_되살아나지_않는다() {
		// R1) 재발급이 RefreshToken 을 읽었다 — 존재하고 계정도 활성이었다
		Long accountId = persistAccount("race@example.com");
		refreshTokenRepository.saveAndFlush(refreshToken(accountId, OLD_TOKEN, OLD_EXPIRES_AT));
		em.clear();

		// D1) 그 사이 탈퇴가 account.deleted = true 와 RefreshToken 삭제를 커밋했다
		refreshTokenRepository.deleteByAccountId(accountId);
		em.flush();
		em.clear();

		// R2) 재발급이 옛 토큰으로 회전을 시도한다
		int affected = refreshTokenRepository.rotate(accountId, OLD_TOKEN, NEW_TOKEN, NEW_EXPIRES_AT);

		assertThat(affected)
				.as("0행이어야 실패로 처리된다. 1행이면 지운 행이 되살아났다는 뜻이다")
				.isZero();
		assertThat(refreshTokenRepository.findByAccountId(accountId))
				.as("삭제한 행이 되살아나지 않는다")
				.isEmpty();
		assertThat(refreshTokenRepository.count()).isZero();
	}

	@Test
	@DisplayName("저장값과 다른 토큰으로 회전하면 0행이고 저장값이 그대로다")
	void 저장값과_다른_토큰으로_회전() {
		Long accountId = persistAccount("stale@example.com");
		refreshTokenRepository.saveAndFlush(refreshToken(accountId, OLD_TOKEN, OLD_EXPIRES_AT));
		em.clear();

		int affected = refreshTokenRepository.rotate(accountId, "someone.elses.token", NEW_TOKEN, NEW_EXPIRES_AT);

		assertThat(affected).isZero();
		RefreshToken found = refreshTokenRepository.findByAccountId(accountId).orElseThrow();
		assertThat(found.getToken()).isEqualTo(OLD_TOKEN);
		assertThat(found.getExpiresAt()).isEqualTo(OLD_EXPIRES_AT);
	}

	@Test
	@DisplayName("deleteByAccountId 는 그 계정의 행을 지운다")
	void 계정별_삭제() {
		Long accountId = persistAccount("logout@example.com");
		refreshTokenRepository.saveAndFlush(refreshToken(accountId, OLD_TOKEN, OLD_EXPIRES_AT));
		em.clear();

		refreshTokenRepository.deleteByAccountId(accountId);
		em.flush();
		em.clear();

		assertThat(refreshTokenRepository.findByAccountId(accountId)).isEmpty();
	}

	private Long persistAccount(String email) {
		return em.persistAndFlush(Account.builder()
				.email(email)
				.password("test-not-a-hash-encoded-password")
				.build()).getId();
	}

	private RefreshToken refreshToken(Long accountId, String token, LocalDateTime expiresAt) {
		return RefreshToken.builder()
				.accountId(accountId)
				.token(token)
				.expiresAt(expiresAt)
				.build();
	}

}
