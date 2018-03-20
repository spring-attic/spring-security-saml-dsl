package acceptance;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import com.example.ColombiaApplication;
import helper.Credentials;
import helper.LoginHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static java.lang.Thread.sleep;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ContextConfiguration(classes = ColombiaApplication.class)
@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("http-metadata")
@DirtiesContext(classMode= DirtiesContext.ClassMode.AFTER_CLASS)
public class HttpMetadataLoginTest {
    private final WebDriver driver = new FirefoxDriver();

    private int port = 8443;
    private String baseUrl;
    private static String username;
    private static String password;

    @BeforeClass
    public static void setupClass() throws IOException {
        Credentials credentials = LoginHelper.loadCredentials();
        username = credentials.getUsername();
        password = credentials.getPassword();
    }

    @Before
    public void setup() {
        driver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
        baseUrl = String.format("https://localhost:%d", port);
        driver.get(baseUrl);
    }

    @After
    public void teardown() {
        driver.close();
    }

    @Test
    public void canLogin() throws InterruptedException {
        driver.findElement(By.name("username")).sendKeys(username);
        driver.findElement(By.name("password")).sendKeys(password);
        driver.findElement(By.id("okta-signin-submit")).submit();
        sleep(1000);
        assertThat(driver.findElement(By.tagName("body")).getText()).contains("Hello world");
    }
}
