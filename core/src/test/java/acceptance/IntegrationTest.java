package acceptance;

import com.example.AuthenticationEventListener;
import com.example.ColombiaApplication;
import helper.Credentials;
import helper.LoginHelper;
import org.assertj.core.api.AbstractCharSequenceAssert;
import org.junit.*;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runner.RunWith;
import org.junit.runners.model.Statement;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ContextConfiguration(classes = ColombiaApplication.class)
@RunWith(SpringJUnit4ClassRunner.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public abstract class IntegrationTest {

	@Autowired
	AuthenticationEventListener authenticationEventListener;

	@ClassRule
	public static IntegrationTestEnabled integrationTestEnabled = new IntegrationTestEnabled();

	protected WebDriver driver = null;

	protected int port = 8443;
	protected String baseUrl;
	protected static String username;
	protected static String password;

	@BeforeClass
	public static void setupClass() throws IOException {
		Credentials credentials = LoginHelper.loadCredentials();
		username = credentials.getUsername();
		password = credentials.getPassword();
	}

	@Before
	public void setup() {
		driver = new FirefoxDriver();
		driver.manage().deleteAllCookies();
		driver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);

		baseUrl = String.format("https://localhost:%d", port);
		driver.get(baseUrl);
	}

	@After
	public void teardown() {
		driver.close();
		authenticationEventListener.clear();
	}

	AbstractCharSequenceAssert<?, String> indexPageHasBeenLoaded() {
		return assertThat(driver.findElement(By.tagName("body")).getText()).contains("Hello world");
	}

	void doLogin() {
		driver.findElement(By.name("username")).sendKeys(username);
		driver.findElement(By.name("password")).sendKeys(password);
		driver.findElement(By.id("okta-signin-submit")).submit();
	}

	public static class IntegrationTestEnabled implements TestRule {
		@Override
		public Statement apply(Statement base, Description description) {
			return new Statement() {
				@Override
				public void evaluate() throws Throwable {
					Assume.assumeThat(
							"the property `-Dtest.sec.saml.dsl.integration` property must be set to true",
							System.getProperty("test.sec.saml.dsl.integration", "false"),
							equalTo("true")
					);
					base.evaluate();
				}
			};
		}
	}
}
