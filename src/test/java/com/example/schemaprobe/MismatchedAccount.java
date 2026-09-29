package com.example.schemaprobe;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * {@code ddl-auto: validate} 가 실제로 적용되는지 확인하기 위한 미끼 엔티티다.
 * {@code account} 테이블에 매핑하되 마이그레이션에 없는 컬럼을 하나 갖는다.
 *
 * <p><b>패키지가 {@code com.example.auth} 밖에 있는 것은 의도다.</b> 안에 두면
 * {@code AuthApplication} 기준의 엔티티 스캔에 걸려 모든 테스트의 스키마 검증이 깨진다.
 * {@link com.example.auth.TestDatabaseEnvironmentTest} 가 {@code @EntityScan} 으로
 * 이 패키지만 따로 올린다.
 */
@Entity
@Table(name = "account")
public class MismatchedAccount {

	@Id
	private Long id;

	/** 마이그레이션(V1)에 없는 컬럼. 검증이 켜져 있으면 기동이 실패해야 한다. */
	@Column(name = "nickname")
	private String nickname;

}
