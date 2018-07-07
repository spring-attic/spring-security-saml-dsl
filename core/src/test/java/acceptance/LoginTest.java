package acceptance;

import static java.lang.Thread.sleep;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import javax.servlet.ServletException;

import org.junit.Test;
import org.openqa.selenium.By;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class LoginTest extends IntegrationTest {

	@Autowired
	private AuthenticationSuccessHandler authenticationSuccessHandler;

	@Test
	public void canLogin() throws InterruptedException, IOException, ServletException {
		driver.findElement(By.name("username")).sendKeys(username);
		driver.findElement(By.name("password")).sendKeys(password);
		driver.findElement(By.id("okta-signin-submit")).submit();
		sleep(1000);

		assertThat(driver.findElement(By.tagName("body")).getText()).contains("Hello world");

		verify(this.authenticationSuccessHandler, times(1))
				.onAuthenticationSuccess(any(), any(), any());
	}

	@Test
	public void cantLoginWithBadCreds() throws InterruptedException {
		driver.findElement(By.name("username")).sendKeys("someguy");
		driver.findElement(By.name("password")).sendKeys("somepass");
		driver.findElement(By.id("okta-signin-submit")).submit();
		sleep(1000);
		assertThat(driver.findElement(By.tagName("body")).getText()).contains("Sign in failed!");
	}
}
