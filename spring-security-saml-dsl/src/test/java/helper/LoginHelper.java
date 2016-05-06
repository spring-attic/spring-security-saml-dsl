package helper;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.Properties;

public class LoginHelper {

    private static final String CREDENTIALS_FILE = "credentials.yml";

    private static final String USERNAME_PROPERTY = "username";
    private static final String PASSWORD_PROPERTY = "password";

    private static final String ENVVAR_USERNAME = "saml_username";
    private static final String ENVVAR_PASSWORD = "saml_password";

    public static Credentials loadCredentials() throws IOException {
        Resource resource = new ClassPathResource(CREDENTIALS_FILE);

        String username;
        String password;

        if (resource.exists()) {
            Properties props = new Properties();
            props.load(resource.getInputStream());
            username = props.getProperty(USERNAME_PROPERTY);
            password = props.getProperty(PASSWORD_PROPERTY);
        } else {
            username = System.getenv(ENVVAR_USERNAME);
            password = System.getenv(ENVVAR_PASSWORD);
        }

        return new Credentials(username, password);
    }
}
