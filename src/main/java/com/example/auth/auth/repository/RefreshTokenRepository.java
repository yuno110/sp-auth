package com.example.auth.auth.repository;

import com.example.auth.auth.entity.RefreshToken;
import jakarta.persistence.LockModeType;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

	/** 계정당 1행이므로 단건이다 (sp-docs/domain-model.md §2.2). */
	Optional<RefreshToken> findByAccountId(Long accountId);

	/**
	 * 잠금 읽기({@code SELECT ... FOR UPDATE}). <b>재사용 유예의 판정이 쓴다</b>
	 * (sp-docs/requirements/member.md §6.3).
	 *
	 * <p><b>최신 커밋 값을 읽어야 해서 잠금 읽기다.</b> MySQL InnoDB 의 REPEATABLE READ 에서 잠그지
	 * 않는 읽기는 트랜잭션의 첫 일관 읽기 때 정해진 스냅샷을 본다. 같은 토큰으로 겹친 재발급의
	 * 둘째는 그 스냅샷을 회전 전에 잡았을 수 있어, 첫째의 회전이 보이지 않고 유예를 놓친다.
	 * 잠금 읽기는 스냅샷이 아니라 최신 커밋 값을 읽고, 첫째가 커밋 전이면 기다린다. 판정보다
	 * 먼저 커밋된 행 삭제(탈퇴·로그아웃·비밀번호 변경)는 행이 없는 것으로 보인다.
	 *
	 * <p>트랜잭션 안에서만 부른다 — 잠금은 그 트랜잭션이 끝날 때 풀린다.
	 */
	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select r from RefreshToken r where r.accountId = :accountId")
	Optional<RefreshToken> findLatestForUpdate(@Param("accountId") Long accountId);

	/**
	 * 회전(Rotation). <b>조건부 UPDATE 하나다.</b> 새 토큰·만료와 함께 직전 토큰(= 제시된 토큰)과
	 * 회전 시각을 <b>같은 문장이</b> 쓴다 (sp-docs/requirements/member.md §6.3,
	 * sp-docs/domain-model.md §2.2).
	 *
	 * <p>반환값은 갱신된 행 수이며 <b>0 이면 회전하지 않은 것이다.</b> 호출자가 반드시 확인한다.
	 * 0 이 나오는 경우는 둘이다 — 행이 이미 삭제됐거나(탈퇴·로그아웃·비밀번호 변경),
	 * {@code currentToken} 이 저장값과 다르다. 뒤쪽은 직전 토큰일 수 있고 그때 재사용 유예를
	 * 판정하는 것은 호출자다 — 이 메서드는 거부하지 않는다.
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
	 * 무너진다. UPDATE 의 WHERE 가 옛 행의 존재를 조건으로 삼으면 R2 는 0행이 된다.
	 *
	 * <p>HTTP 응답으로의 변환은 재발급 경로가 한다 — 여기서 예외로 바꾸지 않는다.
	 *
	 * @param rotatedAt 앱 시계의 값을 마이크로초로 자른 것 (sp-docs/domain-model.md §2.2)
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			update RefreshToken r
			   set r.token = :newToken,
			       r.expiresAt = :newExpiresAt,
			       r.previousToken = :currentToken,
			       r.rotatedAt = :rotatedAt
			 where r.accountId = :accountId
			   and r.token = :currentToken
			""")
	int rotate(@Param("accountId") Long accountId,
			@Param("currentToken") String currentToken,
			@Param("newToken") String newToken,
			@Param("newExpiresAt") LocalDateTime newExpiresAt,
			@Param("rotatedAt") LocalDateTime rotatedAt);

	/**
	 * 로그아웃. <b>대조가 삭제의 조건인 DELETE 하나다</b> (sp-docs/requirements/member.md §6.4).
	 *
	 * <p>그 계정의 행을, 제시된 토큰이 저장된 {@code token} 이나 {@code previous_token} 과 같을
	 * 때만 지운다. 대조한 뒤 따로 지우면 그 사이 커밋된 로그인의 행(새 세션)을 지울 수 있다 —
	 * 회전이 조건부 UPDATE 인 것과 같은 이유다. {@code previous_token} 일치에는 시간 제한이 없다.
	 *
	 * @param accountId 검증된 Access Token 의 {@code sub}
	 * @param refreshToken 본문의 토큰. 서명을 검증하지 않는다 — 문자열 대조가 판정이다
	 * @return 지운 행 수. 0 이면 맞는 세션이 없었다
	 */
	@Modifying(flushAutomatically = true, clearAutomatically = true)
	@Query("""
			delete from RefreshToken r
			 where r.accountId = :accountId
			   and (r.token = :refreshToken or r.previousToken = :refreshToken)
			""")
	int deleteSession(@Param("accountId") Long accountId, @Param("refreshToken") String refreshToken);

	/**
	 * 그 계정의 행을 대조 없이 지운다. <b>비밀번호 변경·계정 탈퇴가 쓴다</b>
	 * (sp-docs/api-contract.md §2.2). 로그아웃은 쓰지 않는다 — {@link #deleteSession}.
	 */
	void deleteByAccountId(Long accountId);

}
