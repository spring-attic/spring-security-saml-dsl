package com.example.dsl;

import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;

import java.util.HashMap;
import java.util.Map;

public class MetadataGeneratorBuilder {
    protected static ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setSignMetadata(true);
        return extendedMetadata;
    }

    protected static KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/colombia.jks");
        Map<String, String> passwords = new HashMap<>();
        passwords.put("colombia", "colombia-password");
        String defaultKey = "colombia";
        return new JKSKeyManager(storeFile, "colombia-password", passwords, defaultKey);
    }

    protected static MetadataGenerator build() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setKeyManager(keyManager());
        metadataGenerator.setEntityId("com:example");
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(keyManager());
        metadataGenerator.setEntityBaseURL("https://localhost:8443");

        return metadataGenerator;
    }
}
