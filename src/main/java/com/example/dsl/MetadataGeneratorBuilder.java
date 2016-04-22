package com.example.dsl;

import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;

public class MetadataGeneratorBuilder {
    public static MetadataGenerator build(
        SAMLEntryPoint samlEntryPoint,
        ExtendedMetadata extendedMetadata,
        KeyManager keyManager, String entityBaseURL, String entityId
    ) {
        MetadataGenerator metadataGenerator = new MetadataGenerator();

        metadataGenerator.setSamlEntryPoint(samlEntryPoint);
        metadataGenerator.setEntityBaseURL(entityBaseURL);
        metadataGenerator.setKeyManager(keyManager);
        metadataGenerator.setEntityId(entityId);
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setExtendedMetadata(extendedMetadata);

        return metadataGenerator;
    }
}
