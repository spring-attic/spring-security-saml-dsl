package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;

@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true)
class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${saml.metadata.path}")
    private String metadataPath;

    @Autowired
    ApplicationEventPublisher applicationEventPublisher;

    @SpyBean
    SimpleUrlAuthenticationSuccessHandler authenticationSuccessHandler;

    @SpyBean
    SimpleUrlAuthenticationFailureHandler authenticationFailureHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        SecurityConfigurer securityConfigurerAdapter =
            saml()
                .identityProvider()
                    .metadataFilePath(metadataPath)
                    .and()
                .serviceProvider()
                .excludeCredential(true)
                .keyStore()
                    .storeFilePath("saml/keystore.jks")
                    .password("secret")
                    .keyname("spring")
                    .keyPassword("secret")
                    .and()
                .protocol("https")
                .hostname("localhost:8443")
                .basePath("/")
                .entityId("com:example")
                .and()
                .successHandler(this.authenticationSuccessHandler)
                .logoutHandler(logoutSuccessHandler())
                .applicationEventPublisher(this.applicationEventPublisher);

        http.apply(securityConfigurerAdapter);

        http
            .requiresChannel()
            .anyRequest().requiresSecure();

        http
            .authorizeRequests()
            .antMatchers("/saml/**").permitAll()
            .antMatchers("/health").permitAll()
            .antMatchers("/error").permitAll()
            .antMatchers("/logged-out.html").permitAll()
            .anyRequest().authenticated();
    }

    private LogoutSuccessHandler logoutSuccessHandler() {
        SimpleUrlLogoutSuccessHandler simpleUrlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
        simpleUrlLogoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        simpleUrlLogoutSuccessHandler.setDefaultTargetUrl("/logged-out.html");
        return simpleUrlLogoutSuccessHandler;
    }

}
