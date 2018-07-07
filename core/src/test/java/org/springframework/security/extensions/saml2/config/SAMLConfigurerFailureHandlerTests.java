package org.springframework.security.extensions.saml2.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StreamUtils;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class SAMLConfigurerFailureHandlerTests {

	@Autowired
	WebApplicationContext wac;

	@Autowired
	AuthenticationFailureHandler authenticationFailureHandler;

	MockMvc mockMvc;

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders
				.webAppContextSetup(wac)
				.apply(springSecurity())
				.build();
	}

	@Test
	public void testCustomAuthenticationFailureHandler() throws Exception {
		// given
		String samlResponse = StreamUtils.copyToString(
				new ClassPathResource("saml/SAMLResponse.xml").getInputStream(),
				StandardCharsets.UTF_8);

		// when
		mockMvc.perform(post("/saml/SSO").param("SAMLResponse", samlResponse));

		// then
		ArgumentCaptor<AuthenticationException> argumentCaptor = ArgumentCaptor.forClass(AuthenticationException.class);
		verify(authenticationFailureHandler, times(1)).onAuthenticationFailure(
				any(HttpServletRequest.class),
				any(HttpServletResponse.class),
				argumentCaptor.capture()
		);
		AuthenticationException authenticationException = argumentCaptor.getValue();
		assertThat(authenticationException)
				.isExactlyInstanceOf(AuthenticationServiceException.class)
				.hasMessageContaining("Incoming SAML message is invalid");

	}

	@Configuration
	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

		@Autowired
		private ApplicationEventPublisher applicationEventPublisher;

		@MockBean
		AuthenticationFailureHandler authenticationFailureHandler;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
					.antMatchers("/saml/**").permitAll()
					.anyRequest().authenticated()
					.and()
					.apply(saml())
					.applicationEventPublisher(this.applicationEventPublisher)
					.failureHandler(this.authenticationFailureHandler)
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
