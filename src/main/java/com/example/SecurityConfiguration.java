package com.example;

import com.example.dsl.OktaConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;

@EnableWebSecurity
@Configuration
@Order
@EnableGlobalMethodSecurity(securedEnabled = true)
class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        SecurityConfigurer securityConfigurerAdapter = new OktaConfigurer();
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
