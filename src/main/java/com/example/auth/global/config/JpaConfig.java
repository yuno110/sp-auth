package com.example.auth.global.config;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.Optional;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

// BaseTimeEntity 의 @CreatedDate·@LastModifiedDate 를 채운다
// (sp-docs/domain-model.md §1.1).
@Configuration
@EnableJpaAuditing(dateTimeProviderRef = "auditingDateTimeProvider")
public class JpaConfig {

	/**
	 * 감사 시각을 <b>초로 잘라서</b> 넣는다.
	 *
	 * <p>자르지 않으면 <b>엔터티의 값과 저장값이 달라진다.</b> 컬럼이 {@code DATETIME}(초 단위)
	 * 이라 MySQL 이 소수부를 <b>반올림</b>하는데 엔터티는 JVM 값(나노초)을 들고 있기 때문이다.
	 * 차이가 소수부에 그치지 않고 <b>초가 달라진다</b> — board 가 쓰기 응답에 {@code createdAt}
	 * 을 실어 그 어긋남이 관측됐다(2026-10-20 실측, sp-docs/api-contract.md §4.3).
	 *
	 * <p><b>이 서비스의 쓰기 응답에는 {@code createdAt} 이 없다</b>(sp-docs/api-contract.md §2.2·§3.1).
	 * 그래도 같이 고치는 이유는 {@code BaseTimeEntity} 가 세 서비스의 복제본이고
	 * (sp-docs/conventions.md §7.1) <b>시각이 만들어지는 방식을 서비스마다 다르게 두면
	 * 다음 사람이 어느 쪽이 맞는지 물어야 하기 때문이다.</b>
	 *
	 * <p>자르면 엔터티 값과 저장값이 같아지므로 두 응답이 일치한다. <b>운영에서 잃는 정밀도는
	 * 없다</b> — {@code DATETIME} 은 애초에 소수부를 담지 않는다. 바뀌는 쪽은 H2 테스트다:
	 * 그동안 마이크로초를 유지해 연속 저장이 모두 다른 값이었는데(B-06 실측) 이제 운영처럼
	 * <b>같은 초가 동률이 된다.</b> 목록 정렬이 {@code id} 를 마지막 키로 쓰는 이유가 그것이고
	 * (sp-docs/api-contract.md §7.1), 그 규칙이 이미 있으므로 순서는 전순서로 남는다.
	 *
	 * <p><b>컬럼을 {@code DATETIME(6)} 으로 바꾸는 쪽을 택하지 않았다.</b> 완료된 마이그레이션을
	 * 고쳐야 하고, <b>방향이 반대다</b> — {@code DATETIME(6)} 은 동률을 <b>없애서</b>
	 * sp-docs/api-contract.md §7.1 의 {@code id} 마지막 키 규칙이 왜 필요한지를 흔들고, 자르기는
	 * 동률을 <b>늘려서</b> 그 규칙을 더 필요하게 만든다. 둘 다 그 동률의 성질을 바꾸므로
	 * <b>그것만으로는 한쪽을 고를 수 없다</b> (이 문단의 앞 판이 그렇게 적었고 D-11 리뷰가 잡았다).
	 *
	 * <p><b>자르기의 위험도 적어 둔다.</b> 자른 값은 최대 1초 이르게 기록되므로 "기동 시각 이후"
	 * 류의 단언과 싸울 수 있다 (sp-docs/api-contract.md §4.3).
	 */
	@Bean
	public DateTimeProvider auditingDateTimeProvider() {
		return new DateTimeProvider() {
			@Override
			public Optional<TemporalAccessor> getNow() {
				return Optional.of(LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS));
			}
		};
	}

}
