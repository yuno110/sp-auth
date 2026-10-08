package com.example.auth.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.account.entity.Account;
import com.example.auth.account.entity.Role;
import com.example.auth.auth.entity.RefreshToken;
import com.example.auth.global.config.JpaConfig;
import com.example.auth.global.config.JwtConfig;
import com.example.auth.global.security.JwtTokenProvider;
import com.example.auth.support.TestRsaKeys;
import jakarta.persistence.Column;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * sp-docs/plan/phase1.md §4 의 AU-03 "검증" 표 중 refresh_token 쪽과, AU-03R(토큰 컬럼 폭 정정)의
 * "검증" 표를 테스트로 옮긴 것이다.
 *
 * <p><b>핵심이 둘이다.</b>
 *
 * <ol>
 * <li>{@code 삭제된_행에_회전하면_0행이고_되살아나지_않는다} — 재현 순서는
 * sp-docs/requirements/member.md §6 에 있다. 회전이 조건부 UPDATE 가 아니라
 * "조회 → 삭제 → INSERT" 면 깨진다. 탈퇴로 지운 행이 되살아나 탈퇴한 계정이 14일간 토큰을
 * 갱신할 수 있게 된다.
 * <li>{@code 실제_발급_토큰이_그대로_저장된다} — <b>AU-03R 이 고친 결함의 회귀 테스트다.</b>
 * 이전 픽스처는 {@code "old.refresh.token"} 같은 17자여서 컬럼이 512자여도 통과했고, 실제 발급
 * 토큰(541~557자)이 들어가는 첫 지점은 세 항목 뒤인 AU-06 이었다
 * (sp-docs/conventions.md §9.2).
 * </ol>
 *
 * <p><b>토큰 픽스처를 실제 길이로 만든다.</b> 길이의 근거는 sp-docs/domain-model.md §2.2 의
 * 측정표다. 지금 발급되는 토큰은 발급 경로로 만들고, 898자(4096비트 키 투영)와 1025자(제약
 * 확인)는 그 경로로 만들 수 없어 같은 문자 집합·모양으로 조립한다.
 *
 * <p>{@code replace = NONE} 이 필요한 이유는 sp-docs/tech-stack.md §5.2 에 있다.
 * {@code refresh_token} 에는 감사 컬럼이 없지만 FK 대상인 {@code account} 를 만들려면
 * {@code @EnableJpaAuditing} 이 필요하므로 {@code JpaConfig} 를 직접 올린다
 * (sp-docs/conventions.md §9.3).
 *
 * <p>{@code JwtConfig}·{@code JwtTokenProvider} 를 함께 올리는 것은 <b>발급 경로가 만든 값</b>으로
 * 저장을 확인하기 위해서다. 개인키는 테스트가 실행 시점에 만든다({@link TestRsaKeys}) —
 * 저장소에 두지 않는다.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({JpaConfig.class, JwtConfig.class, JwtTokenProvider.class})
@ActiveProfiles("test")
class RefreshTokenRepositoryTest {

	/** sp-docs/domain-model.md §2.2 측정표: 발급 토큰 길이의 상한. */
	private static final int MAX_ISSUED_LENGTH = 557;

	/** 같은 표: 키를 4096비트로 회전하면 서명이 683자가 되어 토큰이 약 898자가 된다. */
	private static final int FOUR_K_KEY_LENGTH = 898;

	/** 같은 표: 확정된 컬럼 폭. */
	private static final int COLUMN_LENGTH = 1024;

	private static final String OLD_TOKEN = jwtShapedToken("old", MAX_ISSUED_LENGTH);
	private static final String NEW_TOKEN = jwtShapedToken("new", MAX_ISSUED_LENGTH);
	private static final String OTHERS_TOKEN = jwtShapedToken("others", MAX_ISSUED_LENGTH);

	private static final LocalDateTime OLD_EXPIRES_AT = LocalDateTime.of(2026, 10, 13, 9, 0, 0);
	private static final LocalDateTime NEW_EXPIRES_AT = LocalDateTime.of(2026, 10, 20, 9, 0, 0);

	@DynamicPropertySource
	static void jwtPrivateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private TestEntityManager em;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

	@Test
	@DisplayName("저장 후 조회하면 모든 필드가 일치한다")
	void 저장_후_조회() {
		Long accountId = persistAccount("store@example.com");

		RefreshToken saved = refreshTokenRepository.saveAndFlush(refreshToken(accountId, OLD_TOKEN, OLD_EXPIRES_AT));
		em.clear();

		RefreshToken found = refreshTokenRepository.findById(saved.getId()).orElseThrow();
		assertThat(found.getAccountId()).isEqualTo(accountId);
		assertThat(found.getToken()).isEqualTo(OLD_TOKEN).hasSize(MAX_ISSUED_LENGTH);
		assertThat(found.getExpiresAt()).isEqualTo(OLD_EXPIRES_AT);
	}

	/**
	 * <b>AU-03R 의 회귀 테스트다.</b> 발급 경로가 만든 값을 그대로 저장한다 — 길이를 손으로 적지
	 * 않으므로 claim 집합이나 키 크기가 바뀌면 이 테스트가 먼저 깨진다
	 * (sp-docs/conventions.md §9.2).
	 */
	@Test
	@DisplayName("실제 발급 경로가 만든 Refresh Token 이 그대로 저장되고 왕복한다")
	void 실제_발급_토큰이_그대로_저장된다() {
		Long accountId = persistAccount("issued@example.com");
		String issued = jwtTokenProvider.issue(accountId, Role.USER).refreshToken();

		assertThat(issued.length())
				.as("sp-docs/domain-model.md §2.2 측정표: header 90 + payload 107~123 + 서명 342 + 점 2")
				.isBetween(541, MAX_ISSUED_LENGTH);

		RefreshToken saved = refreshTokenRepository.saveAndFlush(refreshToken(accountId, issued, OLD_EXPIRES_AT));
		em.clear();

		assertThat(refreshTokenRepository.findById(saved.getId()).orElseThrow().getToken())
				.as("잘리거나 바뀌지 않는다")
				.isEqualTo(issued);
	}

	@Test
	@DisplayName("898자 토큰도 저장된다 — 키를 4096비트로 회전해도 들어간다")
	void 키를_4096비트로_회전해도_들어간다() {
		Long accountId = persistAccount("rsa4096@example.com");
		String token = jwtShapedToken("rsa4096", FOUR_K_KEY_LENGTH);

		RefreshToken saved = refreshTokenRepository.saveAndFlush(refreshToken(accountId, token, OLD_EXPIRES_AT));
		em.clear();

		assertThat(refreshTokenRepository.findById(saved.getId()).orElseThrow().getToken())
				.as("768자로 잡으면 이 케이스에서 또 막힌다 (sp-docs/domain-model.md §2.2)")
				.isEqualTo(token);
	}

	/** 폭이 실제로 1024 인지 경계로 본다. 1024 가 들어가고 1025 가 거부되어야 둘 다 성립한다. */
	@Test
	@DisplayName("1024자는 들어가고 1025자는 거부된다 — 길이 제약이 실재한다")
	void 컬럼_폭_경계() {
		Long accountId = persistAccount("boundary@example.com");

		refreshTokenRepository.saveAndFlush(
				refreshToken(accountId, jwtShapedToken("fits", COLUMN_LENGTH), OLD_EXPIRES_AT));
		em.clear();

		Long other = persistAccount("over@example.com");
		RefreshToken tooLong = refreshToken(other, jwtShapedToken("over", COLUMN_LENGTH + 1), OLD_EXPIRES_AT);

		assertThatThrownBy(() -> refreshTokenRepository.saveAndFlush(tooLong))
				.as("제약이 없으면 조용히 잘린다")
				.isInstanceOf(DataIntegrityViolationException.class);
	}

	/**
	 * {@code V2} 를 고치지 않고 {@code V4} 를 더했으므로 이력에 넷이 모두 남아야 한다
	 * (sp-docs/plan/phase1.md §2.4). 체크섬이 어긋나면 컨텍스트가 기동하지 못해 이 테스트는
	 * 실행조차 되지 않는다 — {@code ddl-auto: validate} 통과도 같다.
	 *
	 * <p>엔티티의 {@code length} 와 실제 컬럼 폭을 함께 본다. <b>Hibernate 의 {@code validate} 는
	 * 길이를 비교하지 않으므로</b> 둘이 어긋나도 기동은 성공한다.
	 */
	@Test
	@DisplayName("Flyway 가 V1~V4 를 적용했고 엔티티의 length 가 실제 컬럼 폭과 같다")
	void 마이그레이션과_엔티티가_일치한다() throws Exception {
		List<?> applied = em.getEntityManager()
				.createNativeQuery("select version from flyway_schema_history "
						+ "where success = true order by installed_rank")
				.getResultList();

		assertThat(applied).map(String::valueOf).contains("1", "2", "3", "4");

		Number width = (Number) em.getEntityManager()
				.createNativeQuery("select character_maximum_length from information_schema.columns "
						+ "where table_name = 'refresh_token' and column_name = 'token'")
				.getSingleResult();
		assertThat(width.intValue()).isEqualTo(COLUMN_LENGTH);

		int declared = RefreshToken.class.getDeclaredField("token").getAnnotation(Column.class).length();
		assertThat(declared)
				.as("엔티티와 마이그레이션이 어긋나도 validate 는 통과한다. 여기서 막는다")
				.isEqualTo(width.intValue());
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

	/** {@code V4} 가 폭을 바꾼 뒤에도 {@code uk_refresh_token} 이 남아 있는지 함께 본다. */
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

		int affected = refreshTokenRepository.rotate(accountId, OTHERS_TOKEN, NEW_TOKEN, NEW_EXPIRES_AT);

		assertThat(affected).isZero();
		RefreshToken found = refreshTokenRepository.findByAccountId(accountId).orElseThrow();
		assertThat(found.getToken()).isEqualTo(OLD_TOKEN);
		assertThat(found.getExpiresAt()).isEqualTo(OLD_EXPIRES_AT);
	}

	/**
	 * sp-docs/plan/phase1.md §4 AU-07 검증표의 "값이 같은 토큰으로 회전" 행이다.
	 *
	 * <p><b>이것이 실제로 일어난다.</b> Claim 에 {@code jti} 가 없고 {@code iat} 가 초 단위이므로
	 * 같은 계정이 같은 초에 두 번 발급받으면 토큰 문자열이 완전히 같다
	 * (sp-docs/requirements/member.md §6.2). 그때 재발급은 <b>저장값과 같은 값으로</b> 회전한다.
	 *
	 * <p><b>"0행이면 실패" 판정이 드라이버가 found rows 를 돌려주는 데 의존한다</b> (정본 §6.1 의
	 * 측정표). MySQL(Connector/J 기본)과 H2 는 값이 바뀌지 않아도 1을 돌려주므로 정당한 재발급이
	 * 통과한다. {@code useAffectedRows=true} 를 JDBC URL 에 넣으면 <b>변경된</b> 행을 돌려주므로
	 * 0행이 되어 이 재발급이 거부된다 — 그래서 그 플래그를 쓰지 않는다.
	 *
	 * <p>{@code expires_at} 까지 같은 값으로 쓴다. <b>어느 컬럼도 바뀌지 않는 회전</b>이 found
	 * rows 의존을 드러내는 가장 엄격한 형태다 — 실제 재발급은 토큰이 같아도 {@code expires_at}
	 * 이 밀리초만큼 움직이므로 이보다 느슨하다.
	 */
	@Test
	@DisplayName("값이 같은 토큰으로 회전해도 1행이다 — found rows 에 의존하는 판정이다")
	void 값이_같은_회전도_1행이다() {
		Long accountId = persistAccount("same-value@example.com");
		refreshTokenRepository.saveAndFlush(refreshToken(accountId, OLD_TOKEN, OLD_EXPIRES_AT));
		em.clear();

		int affected = refreshTokenRepository.rotate(accountId, OLD_TOKEN, OLD_TOKEN, OLD_EXPIRES_AT);

		assertThat(affected)
				.as("0행이면 JDBC URL 에 useAffectedRows=true 가 들어온 것이다 "
						+ "(sp-docs/requirements/member.md §6.1)")
				.isOne();
		RefreshToken found = refreshTokenRepository.findByAccountId(accountId).orElseThrow();
		assertThat(found.getToken()).isEqualTo(OLD_TOKEN);
		assertThat(found.getExpiresAt()).isEqualTo(OLD_EXPIRES_AT);
	}

	/**
	 * 위 테스트의 전제를 설정 쪽에서 고정한다 (sp-docs/plan/phase1.md §4 AU-07 완료 기준).
	 *
	 * <p><b>테스트는 H2 로 도므로 이 플래그가 들어와도 깨지지 않는다</b> — MySQL 전용 설정이다.
	 * 그래서 동작이 아니라 커밋되는 설정 파일을 직접 본다. 운영·로컬은 {@code DB_URL} 로 덮을 수
	 * 있으므로 여기서 보는 것은 저장소에 들어 있는 기본값이다.
	 */
	@Test
	@DisplayName("application.yml 의 JDBC URL 에 useAffectedRows 가 없다")
	void 기본_JDBC_URL_에_useAffectedRows_가_없다() throws Exception {
		String applicationYml = new ClassPathResource("application.yml")
				.getContentAsString(StandardCharsets.UTF_8);

		assertThat(applicationYml)
				.as("useAffectedRows=true 는 변경된 행을 돌려주므로 값이 같은 회전이 0행이 되어 "
						+ "정당한 재발급이 거부된다 (sp-docs/requirements/member.md §6.1)")
				.doesNotContain("useAffectedRows");
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

	/**
	 * 발급 토큰과 같은 모양·문자 집합의 {@code length} 자 문자열. base64url 문자와 점 2개로만
	 * 이뤄진다 — 실제 토큰이 그렇다.
	 *
	 * <p>{@code marker} 는 {@code uk_refresh_token} 때문에 값을 서로 다르게 만드는 용도다.
	 */
	private static String jwtShapedToken(String marker, int length) {
		// 점 2개를 뺀 길이를 marker + 채움 문자로 만든다
		String body = marker + "x".repeat(length - 2 - marker.length());
		// 점의 위치를 실제 토큰의 header·payload 경계에 맞춘다 (90, 그다음 107)
		return body.substring(0, 90) + "." + body.substring(90, 197) + "." + body.substring(197);
	}

}
