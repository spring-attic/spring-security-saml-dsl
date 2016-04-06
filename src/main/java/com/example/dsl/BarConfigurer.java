package com.example.dsl;

import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.example.dsl.MetadataGeneratorBuilder.extendedMetadata;

public class BarConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
        public <T> T postProcess(T object) {
            throw new IllegalStateException(
                ObjectPostProcessor.class.getName()
                    + " is a required bean. Ensure you have used @EnableWebSecurity and @Configuration");
        }
    };

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
            .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);
    }

    private WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    private SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    private SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();

        AuthenticationManagerBuilder authenticationManagerBuilder = new AuthenticationManagerBuilder(objectPostProcessor);
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManagerBuilder.build());
        return samlWebSSOProcessingFilter;
    }

    private MetadataGeneratorFilter metadataGeneratorFilter() throws IOException, MetadataProviderException {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/colombia-metadata.xml");

        File oktaMetadata = storeFile.getFile();
        FilesystemMetadataProvider filesystemMetadataProvider = new FilesystemMetadataProvider(oktaMetadata);
        filesystemMetadataProvider.setParserPool(new StaticBasicParserPool());

        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(filesystemMetadataProvider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(false);
        extendedMetadataDelegate.setMetadataRequireSignature(false);

        List<MetadataProvider> providers = new ArrayList<>();
        providers.add(extendedMetadataDelegate);
        CachingMetadataManager cachingMetadataManager = new CachingMetadataManager(providers);

        MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(MetadataGeneratorBuilder.build());
        metadataGeneratorFilter.setManager(cachingMetadataManager);
        return metadataGeneratorFilter;
    }

    private FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
            samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
            new MetadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
            samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
            new SAMLDiscovery()));
        return new FilterChainProxy(chains);
    }
}
