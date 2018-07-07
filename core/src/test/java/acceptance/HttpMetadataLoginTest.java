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
        doLogin();

        System.err.println("Asserting body:"+driver.findElement(By.tagName("body")));

        await().atMost(5, SECONDS).untilAsserted(this::indexPageHasBeenLoaded);
    }
}
