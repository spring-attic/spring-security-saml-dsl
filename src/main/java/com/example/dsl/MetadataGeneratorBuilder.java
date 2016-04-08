package com.example.dsl;

import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

public class MetadataGeneratorBuilder {
    public static MetadataGenerator build(SAMLEntryPoint samlEntryPoint, ExtendedMetadata extendedMetadata, KeyManager keyManager) {
        MetadataGenerator metadataGenerator = new MetadataGenerator();

//        metadataGenerator.setSamlWebSSOFilter();
//        metadataGenerator.setSamlWebSSOHoKFilter();
//        metadataGenerator.setSamlLogoutProcessingFilter();
        metadataGenerator.setSamlEntryPoint(samlEntryPoint);
//        metadataGenerator.setRequestSigned();
//        metadataGenerator.setWantAssertionSigned();
//        metadataGenerator.setNameID();
        metadataGenerator.setEntityBaseURL("https://localhost:8443");
        metadataGenerator.setKeyManager(keyManager);
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
}
