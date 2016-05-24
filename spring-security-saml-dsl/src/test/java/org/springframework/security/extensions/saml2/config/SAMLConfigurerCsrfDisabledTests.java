package org.springframework.security.extensions.saml2.config;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
public class SAMLConfigurerCsrfDisabledTests {
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
	public void disableCsrfWorks() throws Exception {
		mockMvc.perform(post("/public/"))
			// ensure not 403
			.andExpect(status().isNotFound());
	}

	@Configuration
	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.csrf().disable()
				.apply(saml())
					.identityProvider()
						.metadataFilePath("https://dev-348145.oktapreview.com/app/exk5id72igJRNtH5M0h7/sso/saml/metadata")
						.and()
					.serviceProvider()
						.keyStore()
							.storeFilePath("saml/keystore.jks")
							.password("secret")
							.keyname("spring")
							.keyPassword("secret")
							.and()
						.protocol("https")
						.hostname("localhost:8443")
						.basePath("/");
		}
	}
}
