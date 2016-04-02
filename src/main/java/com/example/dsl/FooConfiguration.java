package com.example.dsl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.metadata.MetadataGenerator;

@EnableWebSecurity
@Configuration
@Order
@EnableGlobalMethodSecurity(securedEnabled = true)
class FooConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        SecurityConfigurer securityConfigurerAdapter = new BarConfigurer();
        http.apply(securityConfigurerAdapter);

        http
            .requiresChannel()
            .anyRequest().requiresSecure();
        http
            .httpBasic();
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
