package com.example.auth.global.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * 스케줄링을 켠다. auth 의 첫 스케줄러이고 자리는 sp-docs/conventions.md §1.1 의 {@code global/config} 다
 * (sp-docs/tech-stack.md §4.7).
 *
 * <p>만료된 {@code account_token}·오래된 {@code login_attempt} 의 정리 작업(AU-21)이 이 활성화를 전제한다 — 주기는
 * {@code account-cleanup.interval} 이다. 작업 자체는 여기 두지 않는다({@code AccountCleanup}).
 *
 * <p><b>실행 위치를 고르는 장치를 두지 않는다</b> (sp-docs/tech-stack.md §4.7). 인스턴스가 여럿이면 각자 돌지만 지우는
 * 조건이 같아 결과가 같다. 의존성을 더하지 않는다 — {@code @EnableScheduling} 은 이미 있는 {@code spring-context} 의
 * 것이다.
 */
@Configuration
@EnableScheduling
public class SchedulingConfig {
}
