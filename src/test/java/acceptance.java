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
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

@WebIntegrationTest
@SpringApplicationConfiguration(classes = ColombiaApplication.class)
@RunWith(SpringJUnit4ClassRunner.class)
public class acceptance {

    private final WebDriver driver = new FirefoxDriver();

    private int port = 8443;

    private final RestTemplate restTemplate = new RestTemplate();
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

}
