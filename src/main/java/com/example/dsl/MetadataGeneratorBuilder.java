package com.example.dsl;

import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import java.util.HashMap;
import java.util.Map;

public class MetadataGeneratorBuilder {
    public static MetadataGenerator build(WebSSOProfileOptions webSSOProfileOptions, ExtendedMetadata extendedMetadata) {
        MetadataGenerator metadataGenerator = new MetadataGenerator();

//        metadataGenerator.setSamlWebSSOFilter();
//        metadataGenerator.setSamlWebSSOHoKFilter();
//        metadataGenerator.setSamlLogoutProcessingFilter();
        metadataGenerator.setSamlEntryPoint(getSamlEntryPoint(webSSOProfileOptions));
//        metadataGenerator.setRequestSigned();
//        metadataGenerator.setWantAssertionSigned();
//        metadataGenerator.setNameID();
        metadataGenerator.setEntityBaseURL("https://localhost:8443");
        metadataGenerator.setKeyManager(keyManager());
//        metadataGenerator.setId();
        metadataGenerator.setEntityId("com:example");
//        metadataGenerator.setBindingsSSO();
//        metadataGenerator.setBindingsSLO();
//        metadataGenerator.setBindingsHoKSSO();
        metadataGenerator.setIncludeDiscoveryExtension(false);
//        metadataGenerator.setAssertionConsumerIndex();
        metadataGenerator.setExtendedMetadata(extendedMetadata);

        return metadataGenerator;
    }

    private static SAMLEntryPoint getSamlEntryPoint(WebSSOProfileOptions webSSOProfileOptions) {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions);
        return samlEntryPoint;
    }

    private static KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/colombia.jks");
        Map<String, String> passwords = new HashMap<>();
        passwords.put("colombia", "colombia-password");
        String defaultKey = "colombia";
        return new JKSKeyManager(storeFile, "colombia-password", passwords, defaultKey);
    }
}
