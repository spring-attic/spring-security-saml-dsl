package org.springframework.security.extensions.saml2.config;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.extensions.saml2.config.OktaConfigurer.okta;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class OktaConfigurerTests {
	@Autowired
	WebApplicationContext wac;

	MockMvc mockMvc;

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity())
				.build();
	}

	@Test
	public void protectedUrlRedirectsToDiscovery() throws Exception {
		mockMvc.perform(get("/protected/"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("https://localhost:8443/saml/discovery?entityID=https%3A%2F%2Flocalhost%3A8443%2Fsaml%2Fmetadata&returnIDParam=idp"));
	}

	@Test
	public void discoveryRedirectsLogin() throws Exception {
		mockMvc.perform(get("/saml/discovery").param("entityID","https://localhost:8443/saml/metadata").param("returnIDParam","idp"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("https://localhost:8443/saml/login?disco=true&idp=http%3A%2F%2Fwww.okta.com%2Fexk5id72igJRNtH5M0h7"));
	}

	@Test
	public void loginRendersSAMLRequest() throws Exception {
		mockMvc.perform(get("/saml/login").param("disco", "true").param("idp","http://www.okta.com/exk5id72igJRNtH5M0h7"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("<input type=\"hidden\" name=\"SAMLRequest\" value=\"")));

	}


	@Configuration
	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/saml/**").permitAll()
					.anyRequest().authenticated()
					.and()
				.apply(okta())
					.keyStore()
						.storeFilePath("saml/keystore.jks")
						.password("secret")
						.keyname("spring")
						.keyPassword("secret")
						.and()
					.metadataFilePath("https://dev-348145.oktapreview.com/app/exk5id72igJRNtH5M0h7/sso/saml/metadata")
					.protocol("https")
					.hostname("localhost:8443")
					.basePath("/");
		}
	}
}
