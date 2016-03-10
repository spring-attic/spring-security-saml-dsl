package com.example;

import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class WebSecurityConfiguration {
    @Bean
    public FilesystemMetadataProvider pivotalTestMetadataProvider() throws IOException, MetadataProviderException {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/colombia-metadata.xml");

        File oktaMetadata = storeFile.getFile();
        return new FilesystemMetadataProvider(oktaMetadata);
    }

    @Bean
    public MetadataGenerator metadataGenerator(ExtendedMetadata extendedMetadata) {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId("com:example");
        metadataGenerator.setExtendedMetadata(extendedMetadata);
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        metadataGenerator.setEntityBaseURL("https://localhost:8443/okta");
        return metadataGenerator;
    }

    @Bean
    public SAMLContextProvider contextProvider() {
        SAMLContextProviderLB contextProvider = new SAMLContextProviderLB();
        contextProvider.setScheme("https");
        contextProvider.setServerName("localhost:8443");
        contextProvider.setContextPath("/okta/");
        return contextProvider;
    }

    @Bean
    public PortMapper portMapper() {
        Map<String, String> portMappings = new HashMap<>();
        portMappings.put("8443", "8443");

        PortMapperImpl portMapper = new PortMapperImpl();
        portMapper.setPortMappings(portMappings);
        return portMapper;
    }

    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/colombia.jks");
        Map<String, String> passwords = new HashMap<>();
        passwords.put("colombia", "colombia-password");
        String defaultKey = "colombia";
        return new JKSKeyManager(storeFile, "colombia-password", passwords, defaultKey);
    }
}