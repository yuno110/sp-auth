package com.example.auth.global.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.support.TestRsaKeys;

import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * 감사 시각이 <b>초로 잘려서</b> 들어가는지 본다 (D-11 완료 기준).
 *
 * <p>이 서비스의 쓰기 응답에는 {@code createdAt} 이 없어 그 어긋남이 관측되지 않는다
 * (sp-docs/api-contract.md §2.2·§3.1). 그래도 같이 고치고 같이 잠그는 이유는
 * {@code BaseTimeEntity} 가 세 서비스의 복제본이고(sp-docs/conventions.md §7.1)
 * <b>시각이 만들어지는 방식을 서비스마다 다르게 두지 않기 때문이다.</b>
 *
 * <p>단언은 "소수부가 0" 이다. <b>"엔터티 값과 저장값이 같다" 로는 이 결함을 잡지 못한다</b> —
 * H2 에서 생기는 차이는 초를 넘기지 않기 때문이다(D-11 3라운드 리뷰 실측). 잡히는 것은
 * MySQL 의 반올림이 초를 넘길 때이고, 그것은 H2 로 재현되지 않는다.
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("JpaConfig - 감사 시각")
class JpaConfigTest {

	/**
	 * 전체 컨텍스트를 올리므로 개인키 경로를 넣어야 기동된다 ({@link TestRsaKeys}).
	 * 넣지 않으면 {@code ${JWT_PRIVATE_KEY_LOCATION}} 가 해석되지 않아 컨텍스트가 뜨지 않는다 —
	 * 첫 판에서 그렇게 실패했고, 그 동작은 의도된 것이다(개인키를 저장소에 두지 않는다).
	 */
	@DynamicPropertySource
	static void privateKey(DynamicPropertyRegistry registry) {
		TestRsaKeys.registerPrivateKeyLocation(registry);
	}

	@Autowired
	private DateTimeProvider dateTimeProvider;

	@Test
	@DisplayName("DateTimeProvider 가 주는 시각은 소수부가 0 이다")
	void providerTruncatesToSeconds() {
		Optional<TemporalAccessor> now = this.dateTimeProvider.getNow();

		assertThat(now).isPresent();
		assertThat(now.get().get(ChronoField.NANO_OF_SECOND)).isZero();
	}

}
