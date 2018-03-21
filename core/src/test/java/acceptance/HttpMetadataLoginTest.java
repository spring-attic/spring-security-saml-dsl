package acceptance;

import org.junit.Test;
import org.openqa.selenium.By;
import org.springframework.test.context.ActiveProfiles;

import static java.lang.Thread.sleep;
import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("http-metadata")
public class HttpMetadataLoginTest extends IntegrationTest {

    @Test
    public void canLogin() throws InterruptedException {
        driver.findElement(By.name("username")).sendKeys(username);
        driver.findElement(By.name("password")).sendKeys(password);
        driver.findElement(By.id("okta-signin-submit")).submit();
        sleep(1000);
        System.err.println("Asserting body:"+driver.findElement(By.tagName("body")));
        assertThat(driver.findElement(By.tagName("body")).getText()).contains("Hello world");
    }
}
