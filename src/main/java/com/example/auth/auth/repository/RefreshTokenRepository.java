package com.example.auth.auth.repository;

import com.example.auth.auth.entity.RefreshToken;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

	/** 계정당 1행이므로 단건이다 (sp-docs/domain-model.md §2.2). */
	Optional<RefreshToken> findByAccountId(Long accountId);

	/**
	 * 회전(Rotation). <b>조건부 UPDATE 다.</b>
	 *
	 * <p>반환값은 갱신된 행 수이며 <b>0 이면 실패다.</b> 호출자가 반드시 확인한다.
	 * 0 이 나오는 경우는 둘이다 — 행이 이미 삭제됐거나(탈퇴·로그아웃), {@code currentToken}
	 * 이 저장값과 다르다(이미 회전된 토큰의 재사용).
	 *
	 * <p><b>조회 후 delete + insert 로 하지 않는 이유</b> (sp-docs/requirements/member.md §6):
	 *
	 * <pre>
	 * R1) 재발급: RefreshToken 조회      -&gt; 존재, 계정 활성
	 * D1) 탈퇴:   account.deleted = true; RefreshToken 삭제; COMMIT
	 * R2) 재발급: 옛 행 삭제; 새 행 INSERT; COMMIT   &lt;- 삭제한 행이 되살아난다
	 * </pre>
	 *
	 * <p>되살아나면 탈퇴한 계정이 14일간 토큰을 갱신할 수 있고 "탈퇴 후 최대 30분" 경계가
	 * 무너진다. UPDATE 의 WHERE 가 옛 행의 존재를 조건으로 삼으면 R2 는 0행이 되어 실패한다.
	 *
	 * <p>HTTP 응답으로의 변환은 재발급 경로(AU-07)가 한다 — 여기서 예외로 바꾸지 않는다.
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			update RefreshToken r
			   set r.token = :newToken,
			       r.expiresAt = :newExpiresAt
			 where r.accountId = :accountId
			   and r.token = :currentToken
			""")
	int rotate(@Param("accountId") Long accountId,
			@Param("currentToken") String currentToken,
			@Param("newToken") String newToken,
			@Param("newExpiresAt") LocalDateTime newExpiresAt);

	/** 로그아웃·비밀번호 변경·계정 탈퇴가 쓴다 (sp-docs/api-contract.md §2.1 §2.2). */
	void deleteByAccountId(Long accountId);

}
