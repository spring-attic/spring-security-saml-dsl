package org.springframework.security.extensions.saml2.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opensaml.saml2.core.AuthnContext.KERBEROS_AUTHN_CTX;
import static org.opensaml.saml2.core.AuthnContext.NOMAD_TELEPHONY_AUTHN_CTX;
import static org.opensaml.saml2.core.AuthnContext.SMARTCARD_PKI_AUTHN_CTX;
import static org.opensaml.saml2.core.AuthnContext.SOFTWARE_PKI_AUTHN_CTX;
import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class SAMLConfigurerAuthnContextTests {

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
	public void testCustomAuthnContext() throws Exception {
		MvcResult result = mockMvc.perform(get("/saml/login").param("disco", "true").param("idp", "http://www.okta.com/exk5id72igJRNtH5M0h7"))
				.andExpect(status().isOk())
				.andReturn();
		String content = result.getResponse().getContentAsString();
		String samlRequest = extractSamlRequest(content);
		assertThat(samlRequest).contains(Config.CUSTOM_AUTHN_CTX);
	}

	private static String extractSamlRequest(String content) {
		Document doc = Jsoup.parse(content);
		Element element = doc.select("input[name=SAMLRequest]").first();
		String b64Assertion = element.val();
		return new String(Base64.getDecoder().decode(b64Assertion));
	}

	@Configuration
	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

		static final Collection<String> CUSTOM_AUTHN_CTX = Arrays.asList(
				NOMAD_TELEPHONY_AUTHN_CTX,
				SMARTCARD_PKI_AUTHN_CTX,
				SOFTWARE_PKI_AUTHN_CTX,
				KERBEROS_AUTHN_CTX
		);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.antMatchers("/saml/**").permitAll()
					.anyRequest().authenticated()
					.and()
					.apply(saml())
					.defaultAuthnContexts(CUSTOM_AUTHN_CTX)
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
