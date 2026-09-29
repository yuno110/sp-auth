package com.example.schemaprobe;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;

/**
 * {@link MismatchedAccount} 하나만 올리는 설정이다.
 * {@link com.example.auth.TestDatabaseEnvironmentTest} 가 {@code ApplicationContextRunner} 로 쓴다.
 *
 * <p><b>테스트 클래스 안의 중첩 클래스로 두면 안 된다.</b> Spring TestContext 가 중첩
 * {@code @Configuration} 을 그 테스트의 설정 클래스로 집어가서, 미끼 엔티티가 테스트 본체의
 * 컨텍스트에 올라가 버린다.
 */
@Configuration(proxyBeanMethods = false)
@EntityScan(basePackageClasses = MismatchedAccount.class)
public class SchemaProbeConfig {

}
