package acceptance;

import org.junit.Test;
import org.openqa.selenium.By;

import static java.lang.Thread.sleep;
import static org.assertj.core.api.Assertions.assertThat;

public class LoginTest extends IntegrationTest {

    @Test
    public void canLogin() throws InterruptedException {
        driver.findElement(By.name("username")).sendKeys(username);
        driver.findElement(By.name("password")).sendKeys(password);
        driver.findElement(By.id("okta-signin-submit")).submit();
        sleep(1000);

        assertThat(driver.findElement(By.tagName("body")).getText()).contains("Hello world");
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
