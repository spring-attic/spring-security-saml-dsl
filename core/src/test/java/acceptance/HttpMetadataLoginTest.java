package acceptance;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import org.junit.Test;
import org.openqa.selenium.By;

import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("http-metadata")
public class HttpMetadataLoginTest extends IntegrationTest {

    @Test
    public void canLogin() {
        driver.findElement(By.name("username")).sendKeys(username);
        driver.findElement(By.name("password")).sendKeys(password);
        driver.findElement(By.id("okta-signin-submit")).submit();

        System.err.println("Asserting body:"+driver.findElement(By.tagName("body")));
        await().atMost(5, SECONDS)
                .untilAsserted(() -> assertThat(driver.findElement(By.tagName("body")).getText()).contains("Hello world"));
    }
}
