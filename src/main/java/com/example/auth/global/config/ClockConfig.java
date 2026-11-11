package com.example.auth.global.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 앱 시계. 재발급의 회전 시각과 재사용 유예의 판정 시각이 <b>같은 시계</b>에서 나와야 한다
 * (sp-docs/domain-model.md §2.2, sp-docs/requirements/member.md §6.3) — 그래서 한 빈으로 둔다.
 *
 * <p>{@code LocalDateTime.now()} 와 같은 값을 낸다. 시간대는 실행 환경이 정한다
 * (sp-docs/adr/0011). 빈으로 두는 이유는 테스트가 10초 경계를 시계를 바꿔 끼워 보기 위해서다.
 */
@Configuration
public class ClockConfig {

	@Bean
	public Clock clock() {
		return Clock.systemDefaultZone();
	}

}
