package com.example;

import com.example.dsl.OktaConfigurer;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import static com.example.dsl.OktaConfigurerBuilder.oktaConfigurerBuilder;

@EnableWebSecurity
@Configuration
@Order
@EnableGlobalMethodSecurity(securedEnabled = true)
class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        SecurityConfigurer securityConfigurerAdapter =
                oktaConfigurerBuilder()
                .keystorePath("saml/colombia.jks")
                .keystorePassword("colombia-password")
                .defaultKey("colombia")
                .defaultKeyPassword("colombia-password")
                .metadataFilePath("saml/colombia-metadata.xml")
                .protocol("https")
                .hostname("localhost:8443")
                .basePath("/")
                .entityId("com:example")
        .build();

        http.apply(securityConfigurerAdapter);

        http
            .requiresChannel()
            .anyRequest().requiresSecure();
        http
            .csrf()
            .disable();

        http
            .authorizeRequests()
            .antMatchers("/saml/**").permitAll()
            .antMatchers("/health").permitAll()
            .antMatchers("/error").permitAll()
            .anyRequest().authenticated();
    }
}
