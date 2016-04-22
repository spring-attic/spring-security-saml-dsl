package acceptance;

import com.example.ColombiaApplication;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

@WebIntegrationTest
@SpringApplicationConfiguration(classes = ColombiaApplication.class)
@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("http-metadata")
public class HttpMetadataLoginTest {
    private final WebDriver driver = new FirefoxDriver();

    private int port = 8443;
    private String baseUrl;
    private static String username;
    private static String password;

    @BeforeClass
    public static void setupClass() throws IOException {
        Resource resource = new ClassPathResource("credentials.yml");
        Properties props = new Properties();
        props.load(resource.getInputStream());

        username = props.getProperty("username");
        password = props.getProperty("password");
    }

    @Before
    public void setup() {
        baseUrl = String.format("https://localhost:%d", port);
        driver.get(baseUrl);
    }

    @Test
    public void canLogin() {
        driver.findElement(By.name("username")).sendKeys(username);
        driver.findElement(By.name("password")).sendKeys(password);
        driver.findElement(By.name("login")).submit();

        assertThat(driver.findElement(By.tagName("body")).getText()).contains("Hello world");
    }

    @Test
    public void cantLoginWithBadCreds() {
        driver.findElement(By.name("username")).sendKeys("someguy");
        driver.findElement(By.name("password")).sendKeys("somepass");
        driver.findElement(By.name("login")).submit();

        assertThat(driver.findElement(By.tagName("body")).getText()).contains("Sign in failed!");
    }
}
