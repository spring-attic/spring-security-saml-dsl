package com.example.dsl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.websso.WebSSOProfile;

public class SAMLDslEntryPoint extends org.springframework.security.saml.SAMLEntryPoint {
    /**
     * Metadata manager, cannot be null, must be set.
     * It is set directly in the custom config, so can be optional here.
     * User could override it if desired.
     *
     * @param metadata manager
     */
    @Autowired(required = false)
    @Override
    public void setMetadata(MetadataManager metadata) {
        super.setMetadata(metadata);
    }

    /**
     * Logger for SAML events, cannot be null, must be set.
     *
     * @param samlLogger logger
     *                   It is set in the custom config, so can be optional here.
     *                   User could override it if desired.
     */
    @Autowired(required = false)
    @Override
    public void setSamlLogger(SAMLLogger samlLogger) {
        super.setSamlLogger(samlLogger);
    }

    /**
     * Profile for consumption of processed messages, cannot be null, must be set.
     * It is set in the custom config, so can be optional here.
     * User could override it if desired.
     *
     * @param webSSOprofile profile
     */
    @Autowired(required = false)
    @Qualifier("webSSOprofile")
    @Override
    public void setWebSSOprofile(WebSSOProfile webSSOprofile) {
        super.setWebSSOprofile(webSSOprofile);
    }

    /**
     * Sets entity responsible for populating local entity context data.
     * It is set in the custom config, so can be optional here.
     * User could override it if desired.
     *
     * @param contextProvider provider implementation
     */
    @Autowired(required = false)
    @Override
    public void setContextProvider(SAMLContextProvider contextProvider) {
        super.setContextProvider(contextProvider);
    }
}
