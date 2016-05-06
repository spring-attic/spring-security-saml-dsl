package org.springframework.security.extensions.saml2.config;

import org.apache.commons.httpclient.HttpClient;
import org.opensaml.Configuration;
import org.opensaml.PaosBootstrap;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.CertPathPKIXTrustEvaluator;
import org.opensaml.xml.security.x509.PKIXTrustEvaluator;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.trust.MetadataCredentialResolver;
import org.springframework.security.saml.trust.PKIXInformationResolver;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.File;
import java.io.IOException;
import java.util.*;

/*
 Spring security configurer for okta.
 @Author Mark Douglass
 @Author Jean de Klerk
*/
public class OktaConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private KeyStore keyStore = new KeyStore();
    private String metadataFilePath;
    private String protocol;
    private String hostName;
    private String basePath;
    private String entityId;

    private WebSSOProfileOptions webSSOProfileOptions = webSSOProfileOptions();
    private ExtendedMetadata extendedMetadata = extendedMetadata();
    private StaticBasicParserPool parserPool = staticBasicParserPool();
    private SAMLProcessor samlProcessor = samlProcessor();
    private SAMLDefaultLogger samlLogger = new SAMLDefaultLogger();
    private SAMLAuthenticationProvider samlAuthenticationProvider;
    private MetadataProvider metadataProvider;
    private ExtendedMetadataDelegate extendedMetadataDelegate;
    private KeyManager keyManager;
    private CachingMetadataManager cachingMetadataManager;
    private WebSSOProfile webSSOProfile;
    private SAMLUserDetailsService samlUserDetailsService;

    private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
        public <T> T postProcess(T object) {
            return object;
        }
    };

    private OktaConfigurer() {
    }

    @Override
    public void init(HttpSecurity http) {

        metadataProvider = metadataProvider();
        extendedMetadataDelegate = extendedMetadataDelegate();
        keyManager = keyManager();
        cachingMetadataManager = cachingMetadataManager();
        webSSOProfile = new WebSSOProfileImpl(samlProcessor, cachingMetadataManager);
        samlAuthenticationProvider = samlAuthenticationProvider();

        bootstrap();

        SAMLContextProvider contextProvider = contextProvider();
        SAMLEntryPoint samlEntryPoint = samlEntryPoint(contextProvider);

        try {
            http
                .httpBasic()
                .authenticationEntryPoint(samlEntryPoint)
                .and()
                .csrf()
                .ignoringAntMatchers("/saml/SSO");

        } catch (Exception e) {
            e.printStackTrace();
        }

        http
            .addFilterBefore(metadataGeneratorFilter(samlEntryPoint), ChannelProcessingFilter.class)
            .addFilterAfter(samlFilter(samlEntryPoint, contextProvider), BasicAuthenticationFilter.class)
            .authenticationProvider(samlAuthenticationProvider);
    }

    public static OktaConfigurer okta() {
        return new OktaConfigurer();
    }

    public KeyStore keyStore() {
        return keyStore;
    }

    public OktaConfigurer metadataFilePath(String metadataFilePath) {
        this.metadataFilePath = metadataFilePath;
        return this;
    }

    public OktaConfigurer protocol(String protocol) {
        this.protocol = protocol;
        return this;
    }

    public OktaConfigurer hostname(String hostname) {
        this.hostName = hostname;
        return this;
    }

    public OktaConfigurer basePath(String basePath) {
        this.basePath = basePath;
        return this;
    }

    public OktaConfigurer entityId(String entityId) {
        this.entityId = entityId;
        return this;
    }

    public OktaConfigurer userDetailsService(SAMLUserDetailsService samlUserDetailsService) {
        this.samlUserDetailsService = samlUserDetailsService;
        return this;
    }

    private String entityBaseURL() {
        String entityBaseURL = hostName + "/" + basePath;
        entityBaseURL = entityBaseURL.replaceAll("//", "/").replaceAll("/$", "");
        entityBaseURL = protocol + "://" + entityBaseURL;
        return entityBaseURL;
    }

    private SAMLEntryPoint samlEntryPoint(SAMLContextProvider contextProvider) {
        SAMLEntryPoint samlEntryPoint = new SAMLDslEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions);
        samlEntryPoint.setWebSSOprofile(webSSOProfile);
        samlEntryPoint.setContextProvider(contextProvider);
        samlEntryPoint.setMetadata(cachingMetadataManager);
        samlEntryPoint.setSamlLogger(samlLogger);
        return samlEntryPoint;
    }

    private SAMLProcessor samlProcessor() {
        Collection<SAMLBinding> bindings = new ArrayList<>();
        bindings.add(httpRedirectDeflateBinding(parserPool));
        bindings.add(httpPostBinding(parserPool));
        return new SAMLProcessorImpl(bindings);
    }

    private CachingMetadataManager cachingMetadataManager() {
        List<MetadataProvider> providers = new ArrayList<>();
        providers.add(extendedMetadataDelegate);

        CachingMetadataManager cachingMetadataManager = null;
        try {
            cachingMetadataManager = new CachingMetadataManager(providers);
        } catch (MetadataProviderException e) {
            e.printStackTrace();
        }

        cachingMetadataManager.setKeyManager(keyManager);
        return cachingMetadataManager;
    }

    private StaticBasicParserPool staticBasicParserPool() {
        StaticBasicParserPool parserPool = new StaticBasicParserPool();
        try {
            parserPool.initialize();
        } catch (XMLParserException e) {
            e.printStackTrace();
        }
        return parserPool;
    }

    private ExtendedMetadataDelegate extendedMetadataDelegate() {
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(metadataProvider, extendedMetadata);
        extendedMetadataDelegate.setMetadataTrustCheck(false);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        return extendedMetadataDelegate;
    }

    private MetadataProvider metadataProvider() {
        if (metadataFilePath.startsWith("http")) {
            return httpMetadataProvider();
        } else {
            return fileSystemMetadataProvider();
        }
    }

    private HTTPMetadataProvider httpMetadataProvider() {
        try {
            HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(new Timer(), new HttpClient(), metadataFilePath);
            httpMetadataProvider.setParserPool(parserPool);
            return httpMetadataProvider;
        } catch (MetadataProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    private FilesystemMetadataProvider fileSystemMetadataProvider() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource metadataResource = loader.getResource(metadataFilePath);

        File oktaMetadata = null;
        try {
            oktaMetadata = metadataResource.getFile();
        } catch (IOException e) {
            e.printStackTrace();
        }

        FilesystemMetadataProvider filesystemMetadataProvider = null;
        try {
            filesystemMetadataProvider = new FilesystemMetadataProvider(oktaMetadata);
        } catch (MetadataProviderException e) {
            e.printStackTrace();
        }
        filesystemMetadataProvider.setParserPool(parserPool);

        return filesystemMetadataProvider;
    }

    private ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setSignMetadata(true);
        return extendedMetadata;
    }

    private WebSSOProfileOptions webSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    private void bootstrap() {
        try {
            PaosBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }

        NamedKeyInfoGeneratorManager manager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
        X509KeyInfoGeneratorFactory generator = new X509KeyInfoGeneratorFactory();
        generator.setEmitEntityCertificate(true);
        generator.setEmitEntityCertificateChain(true);
        manager.registerFactory(SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR, generator);
    }

    private HTTPPostBinding httpPostBinding(ParserPool parserPool) {
        return new HTTPPostBinding(parserPool, VelocityFactory.getEngine());
    }

    private HTTPRedirectDeflateBinding httpRedirectDeflateBinding(ParserPool parserPool) {
        return new HTTPRedirectDeflateBinding(parserPool);
    }

    private SAMLProcessingFilter samlWebSSOProcessingFilter(SAMLAuthenticationProvider samlAuthenticationProvider, SAMLContextProvider contextProvider, SAMLProcessor samlProcessor) throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();

        AuthenticationManagerBuilder authenticationManagerBuilder = new AuthenticationManagerBuilder(objectPostProcessor);
        authenticationManagerBuilder.authenticationProvider(samlAuthenticationProvider);
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManagerBuilder.build());
        samlWebSSOProcessingFilter.setContextProvider(contextProvider);
        samlWebSSOProcessingFilter.setSAMLProcessor(samlProcessor);
        return samlWebSSOProcessingFilter;
    }

    private MetadataGeneratorFilter metadataGeneratorFilter(SAMLEntryPoint samlEntryPoint) {
        MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(getMetadataGenerator(samlEntryPoint));
        metadataGeneratorFilter.setManager(cachingMetadataManager);
        return metadataGeneratorFilter;
    }

    private FilterChainProxy samlFilter(SAMLEntryPoint samlEntryPoint, SAMLContextProvider contextProvider) {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
            samlEntryPoint));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
            new MetadataDisplayFilter()));
        try {
            chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter(samlAuthenticationProvider, contextProvider, samlProcessor)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        SAMLDiscovery samlDiscovery = new SAMLDiscovery();
        samlDiscovery.setMetadata(cachingMetadataManager);
        samlDiscovery.setContextProvider(contextProvider);
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
            samlDiscovery));
        return new FilterChainProxy(chains);
    }

    private KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource(keyStore.getStoreFilePath());
        Map<String, String> passwords = new HashMap<>();
        passwords.put(keyStore.getKeyname(), keyStore.getKeyPassword());
        return new JKSKeyManager(storeFile, keyStore.getPassword(), passwords, keyStore.getKeyname());
    }

    private SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        samlAuthenticationProvider.setSamlLogger(samlLogger);
        samlAuthenticationProvider.setConsumer(new WebSSOProfileConsumerImpl());
        samlAuthenticationProvider.setUserDetails(this.samlUserDetailsService);
        return samlAuthenticationProvider;
    }

    private SAMLContextProvider contextProvider() {
        SAMLContextProviderLB contextProvider = new SAMLContextProviderLB();
        contextProvider.setMetadata(cachingMetadataManager);
        contextProvider.setScheme(protocol);
        contextProvider.setServerName(hostName);
        contextProvider.setContextPath(basePath);
        contextProvider.setKeyManager(keyManager);

        MetadataCredentialResolver resolver = new MetadataCredentialResolver(cachingMetadataManager, keyManager);
        PKIXTrustEvaluator pkixTrustEvaluator = new CertPathPKIXTrustEvaluator();
        PKIXInformationResolver pkixInformationResolver = new PKIXInformationResolver(resolver, cachingMetadataManager, keyManager);

        contextProvider.setPkixResolver(pkixInformationResolver);
        contextProvider.setPkixTrustEvaluator(pkixTrustEvaluator);
        contextProvider.setMetadataResolver(resolver);

        return contextProvider;
    }

    private MetadataGenerator getMetadataGenerator(SAMLEntryPoint samlEntryPoint) {
        MetadataGenerator metadataGenerator = new MetadataGenerator();

        metadataGenerator.setSamlEntryPoint(samlEntryPoint);
        metadataGenerator.setEntityBaseURL(entityBaseURL());
        metadataGenerator.setKeyManager(keyManager);
        metadataGenerator.setEntityId(entityId);
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setExtendedMetadata(extendedMetadata);

        return metadataGenerator;
    }

    public class KeyStore {
        private String storeFilePath;
        private String password;
        private String keyname;
        private String keyPassword;

        public KeyStore storeFilePath(String storeFilePath) {
            this.storeFilePath = storeFilePath;
            return this;
        }

        public KeyStore password(String password) {
            this.password = password;
            return this;
        }

        public KeyStore keyname(String keyname) {
            this.keyname = keyname;
            return this;
        }

        public KeyStore keyPassword(String keyPasswordword) {
            this.keyPassword = keyPasswordword;
            return this;
        }

        public OktaConfigurer and() {
            return OktaConfigurer.this;
        }

        public String getStoreFilePath() {
            return storeFilePath;
        }

        public String getPassword() {
            return password;
        }

        public String getKeyname() {
            return keyname;
        }

        public String getKeyPassword() {
            return keyPassword;
        }

        @Override
        public String toString() {
            return "KeyStore{" +
                "storeFilePath='" + storeFilePath + '\'' +
                ", password='" + password + '\'' +
                ", keyname='" + keyname + '\'' +
                ", keyPassword='" + keyPassword + '\'' +
                '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            KeyStore keyStore = (KeyStore) o;

            if (storeFilePath != null ? !storeFilePath.equals(keyStore.storeFilePath) : keyStore.storeFilePath != null)
                return false;
            if (password != null ? !password.equals(keyStore.password) : keyStore.password != null) return false;
            if (keyname != null ? !keyname.equals(keyStore.keyname) : keyStore.keyname != null) return false;
            return keyPassword != null ? keyPassword.equals(keyStore.keyPassword) : keyStore.keyPassword == null;

        }

        @Override
        public int hashCode() {
            int result = storeFilePath != null ? storeFilePath.hashCode() : 0;
            result = 31 * result + (password != null ? password.hashCode() : 0);
            result = 31 * result + (keyname != null ? keyname.hashCode() : 0);
            result = 31 * result + (keyPassword != null ? keyPassword.hashCode() : 0);
            return result;
        }
    }
}
