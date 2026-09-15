package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class AuthApplicationTest {

	@Test
	@DisplayName("애플리케이션 컨텍스트가 예외 없이 로딩된다")
	void 컨텍스트가_로딩된다() {
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"private.pem",
			"src/main/resources/application-local.yml",
			"local.env"
	})
	@DisplayName("비밀 값 경로는 git 이 무시한다")
	void 비밀_값_경로가_무시된다(String path) throws Exception {
		assertThat(gitCheckIgnoreExitCode(path))
				.as("git check-ignore %s (0=무시됨, 1=추적 대상, 128=git 오류)", path)
				.isZero();
	}

	private int gitCheckIgnoreExitCode(String path) throws Exception {
		Process process = new ProcessBuilder("git", "check-ignore", "-q", path)
				.directory(new File(System.getProperty("user.dir")))
				.redirectErrorStream(true)
				.start();
		assertThat(process.waitFor(10, TimeUnit.SECONDS))
				.as("git check-ignore 가 10초 안에 끝난다")
				.isTrue();
		return process.exitValue();
	}

}
