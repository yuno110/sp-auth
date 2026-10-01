package com.example.securityprobe;

import com.example.auth.global.security.CurrentAccount;
import com.example.auth.global.security.LoginAccount;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code @CurrentAccount} 리졸버가 <b>등록되어 있는지</b>까지 확인할 대상이다. 업무 컨트롤러는
 * AU-05 부터 생긴다.
 *
 * <p>리졸버가 등록되지 않으면 Spring 이 {@code LoginAccount} 를 모델 속성으로 보고 빈 record 를
 * 만들어 넘긴다 — 예외 없이 {@code accountId = null} 이 되는 조용한 실패다. HTTP 경로로
 * 확인해야 그것이 드러난다.
 *
 * <p><b>{@code com.example.auth} 밖에 둔다.</b> 안에 두면 컴포넌트 스캔에 걸려 다른 테스트의
 * 컨텍스트에도 이 경로가 생긴다. {@code SecurityConfigTest} 가 {@code @TestConfiguration} 으로
 * 자기 컨텍스트에만 등록한다. ({@code com.example.schemaprobe} 와 같은 이유다.)
 */
@RestController
public class CurrentAccountProbeController {

	/** SecurityConfig 에 선언되지 않은 경로이므로 {@code anyRequest()} 규칙이 적용된다. */
	@GetMapping("/test/current-account")
	public LoginAccount currentAccount(@CurrentAccount LoginAccount loginAccount) {
		return loginAccount;
	}

}
