package acceptance;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import javax.servlet.ServletException;

import com.example.AuthenticationEventListener;
import org.junit.Test;
import org.openqa.selenium.By;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class LoginTest extends IntegrationTest {

	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;

	@Test
	public void canLogin() throws IOException, ServletException {
		driver.findElement(By.name("username")).sendKeys(username);
		driver.findElement(By.name("password")).sendKeys(password);
		driver.findElement(By.id("okta-signin-submit")).submit();

		await().atMost(5, SECONDS)
				.untilAsserted(() -> assertThat(driver.findElement(By.tagName("body")).getText()).contains("Hello world"));

		verify(authenticationSuccessHandler, times(1))
				.onAuthenticationSuccess(any(), any(), any());

		assertThat(authenticationEventListener.getReceivedEvents())
				.filteredOn(e -> e instanceof InteractiveAuthenticationSuccessEvent)
				.hasSize(1);

		assertThat(authenticationEventListener.getReceivedEvents())
				.filteredOn(e -> e instanceof AuthenticationSuccessEvent)
				.hasSize(1);
	}

	@Test
	public void cantLoginWithBadCreds() {
		driver.findElement(By.name("username")).sendKeys("someguy");
		driver.findElement(By.name("password")).sendKeys("somepass");
		driver.findElement(By.id("okta-signin-submit")).submit();

		await().atMost(5, SECONDS)
				.untilAsserted(() -> assertThat(driver.findElement(By.tagName("body")).getText()).contains("Sign in failed!"));

	}
}
