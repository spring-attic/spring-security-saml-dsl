package com.example.dsl;

public class OktaConfigurerBuilder {

    private String keystorePath;
    private String keystorePassword;
    private String defaultKey;
    private String defaultKeyPassword;

    private String metadataFilePath = "saml/metadata.xml";
    private String protocol = "https";
    private String basePath = "/";
    private String hostname;
    private String entityId;

    private OktaConfigurerBuilder() {};

    public static OktaConfigurerBuilder oktaConfigurerBuilder() {
        return new OktaConfigurerBuilder();
    }

    public OktaConfigurerBuilder keystorePath(String keystorePath) {
        this.keystorePath = keystorePath;
        return this;
    }

    public OktaConfigurerBuilder keystorePassword(String keystorePassword) {
        this.keystorePassword = keystorePassword;
        return this;
    }

    public OktaConfigurerBuilder defaultKey(String defaultKey) {
        this.defaultKey = defaultKey;
        return this;
    }

    public OktaConfigurerBuilder defaultKeyPassword(String defaultKeyPassword) {
        this.defaultKeyPassword = defaultKeyPassword;
        return this;
    }

    public OktaConfigurerBuilder metadataFilePath(String metadataFilePath) {
        this.metadataFilePath = metadataFilePath;
        return this;
    }

    public OktaConfigurerBuilder protocol(String protocol) {
        this.protocol = protocol;
        return this;
    }

    public OktaConfigurerBuilder basePath(String basePath) {
        this.basePath = basePath;
        return this;
    }

    public OktaConfigurerBuilder hostname(String hostname) {
        this.hostname = hostname;
        return this;
    }

    public OktaConfigurerBuilder entityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    public OktaConfigurer build() {
        return new OktaConfigurer(keystorePath, keystorePassword, defaultKey, defaultKeyPassword, metadataFilePath, protocol, hostname, basePath, entityId);
    }
}
