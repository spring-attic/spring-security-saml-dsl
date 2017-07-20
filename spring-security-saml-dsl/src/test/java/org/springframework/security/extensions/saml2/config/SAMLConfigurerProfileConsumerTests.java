package org.springframework.security.extensions.saml2.config;


import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.NameID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StreamUtils;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class SAMLConfigurerProfileConsumerTests {

    @Autowired
    private WebSSOProfileConsumerImpl webSSOProfileConsumer;

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
    public void webSSOProfileConsumerIsInjectedViaDSL() throws Exception {
		ArgumentCaptor<SAMLMessageContext> samlMessageContextCaptor = ArgumentCaptor.forClass(SAMLMessageContext.class);

		when(webSSOProfileConsumer.processAuthenticationResponse(samlMessageContextCaptor.capture()))
				.thenReturn(stubSAMLCredential());

		String samlResponse = StreamUtils.copyToString(
				new ClassPathResource("saml/SAMLResponse.xml").getInputStream(),
				StandardCharsets.UTF_8);

		mockMvc.perform(post("/saml/SSO").param("SAMLResponse", samlResponse));

        verify(webSSOProfileConsumer).processAuthenticationResponse(samlMessageContextCaptor.capture());

		SAMLMessageContext samlMessageContext = samlMessageContextCaptor.getValue();

		assertThat(samlMessageContext).isNotNull();
		assertThat(samlMessageContext.getInboundSAMLMessageId()).isEqualTo("id61844979402263501352984461");
		assertThat(samlMessageContext.getPeerEntityId()).isEqualTo("http://www.okta.com/exkb5v2p0pp35JFKa0h7");
	}

	private SAMLCredential stubSAMLCredential() {
		return new SAMLCredential(
				mock(NameID.class),
				mock(Assertion.class),
				"entity",
				"local");
	}

	@Configuration
	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

        @Bean
        public WebSSOProfileConsumerImpl webSSOProfileConsumer() {
            return mock(WebSSOProfileConsumerImpl.class);
        }

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.antMatchers("/saml/**").permitAll()
					.anyRequest().authenticated()
					.and()
				.apply(saml())
					.identityProvider()
						.metadataFilePath("https://dev-547916.oktapreview.com/app/exkb5v2p0pp35JFKa0h7/sso/saml/metadata")
						.and()
                    .webSSOProfileConsumer(webSSOProfileConsumer())
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
