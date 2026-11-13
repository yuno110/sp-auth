package com.example.auth.mail;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * 메일 설정 클래스를 등록한다 (sp-docs/tech-stack.md §4.7).
 *
 * <p>기동 가드({@link MailStartupGuard})는 빈이 아니다 — 컨텍스트보다 먼저 돌아야 해서 환경 후처리기로
 * {@code META-INF/spring.factories} 가 등록한다. 발송 실행기는 스케줄링 활성화와 함께
 * {@code global/config} 에 둔다 (sp-docs/conventions.md §1.1).
 */
@Configuration
@EnableConfigurationProperties(MailSettings.class)
public class MailConfig {

	/** 운영 프로파일의 이름. {@code application-prod.yml} 이 이 이름으로 읽힌다. */
	static final String PROD_PROFILE = "prod";

}
