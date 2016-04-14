package com.example.dsl;

import org.opensaml.Configuration;
import org.opensaml.PaosBootstrap;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
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
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.trust.MetadataCredentialResolver;
import org.springframework.security.saml.trust.PKIXInformationResolver;
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
import com.example.dsl.overrides.SAMLDslEntryPoint;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class OktaConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private WebSSOProfileOptions webSSOProfileOptions = webSSOProfileOptions();
    private ExtendedMetadata extendedMetadata = extendedMetadata();
    private StaticBasicParserPool parserPool = staticBasicParserPool();
    private FilesystemMetadataProvider filesystemMetadataProvider = fileSystemMetadataProvider(parserPool);
    private ExtendedMetadataDelegate extendedMetadataDelegate = extendedMetadataDelegate(extendedMetadata, filesystemMetadataProvider);
    private KeyManager keyManager = keyManager();
    private CachingMetadataManager cachingMetadataManager = cachingMetadataManager(extendedMetadataDelegate, keyManager);
    private SAMLProcessor samlProcessor = samlProcessor(parserPool);
    private WebSSOProfile webSSOProfile = new WebSSOProfileImpl(samlProcessor, cachingMetadataManager);
    private SAMLDefaultLogger samlLogger = new SAMLDefaultLogger();
    private SAMLAuthenticationProvider samlAuthenticationProvider = samlAuthenticationProvider(samlLogger);

    private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
        public <T> T postProcess(T object) {
            return object;
        }
    };

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.authenticationProvider(samlAuthenticationProvider);

        bootstrap();

        SAMLContextProvider contextProvider = contextProvider();
        SAMLEntryPoint samlEntryPoint = samlEntryPoint(contextProvider);

        http.httpBasic().authenticationEntryPoint(samlEntryPoint);

        http
            .addFilterBefore(metadataGeneratorFilter(samlEntryPoint), ChannelProcessingFilter.class)
            .addFilterAfter(samlFilter(samlEntryPoint, contextProvider), BasicAuthenticationFilter.class);
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

    private SAMLProcessor samlProcessor(StaticBasicParserPool parserPool) {
        Collection<SAMLBinding> bindings = new ArrayList<>();
        bindings.add(httpRedirectDeflateBinding(parserPool));
        bindings.add(httpPostBinding(parserPool));
        return new SAMLProcessorImpl(bindings);
    }

    private CachingMetadataManager cachingMetadataManager(ExtendedMetadataDelegate extendedMetadataDelegate, KeyManager keyManager) {
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

    private ExtendedMetadataDelegate extendedMetadataDelegate(ExtendedMetadata extendedMetadata, FilesystemMetadataProvider filesystemMetadataProvider) {
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(filesystemMetadataProvider, extendedMetadata);
        extendedMetadataDelegate.setMetadataTrustCheck(false);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        return extendedMetadataDelegate;
    }

    private FilesystemMetadataProvider fileSystemMetadataProvider(ParserPool parserPool) {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/colombia-metadata.xml");

        File oktaMetadata = null;
        try {
            oktaMetadata = storeFile.getFile();
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

    private void bootstrap() throws ConfigurationException {
        PaosBootstrap.bootstrap();

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

    private MetadataGeneratorFilter metadataGeneratorFilter(SAMLEntryPoint samlEntryPoint) throws IOException, MetadataProviderException, XMLParserException {

        MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(MetadataGeneratorBuilder.build(samlEntryPoint, extendedMetadata, keyManager));
        metadataGeneratorFilter.setManager(cachingMetadataManager);
        return metadataGeneratorFilter;
    }

    private FilterChainProxy samlFilter(SAMLEntryPoint samlEntryPoint, SAMLContextProvider contextProvider) throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
            samlEntryPoint));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
            new MetadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
            samlWebSSOProcessingFilter(samlAuthenticationProvider, contextProvider, samlProcessor)));
        SAMLDiscovery samlDiscovery = new SAMLDiscovery();
        samlDiscovery.setMetadata(cachingMetadataManager);
        samlDiscovery.setContextProvider(contextProvider);
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
            samlDiscovery));
        return new FilterChainProxy(chains);
    }

    private static KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/colombia.jks");
        Map<String, String> passwords = new HashMap<>();
        passwords.put("colombia", "colombia-password");
        String defaultKey = "colombia";
        return new JKSKeyManager(storeFile, "colombia-password", passwords, defaultKey);
    }

    private SAMLAuthenticationProvider samlAuthenticationProvider(SAMLLogger samlLogger) {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        samlAuthenticationProvider.setSamlLogger(samlLogger);
        samlAuthenticationProvider.setConsumer(new WebSSOProfileConsumerImpl());
        return samlAuthenticationProvider;
    }

    private SAMLContextProvider contextProvider() {
        SAMLContextProviderLB contextProvider = new SAMLContextProviderLB();
        contextProvider.setMetadata(cachingMetadataManager);
        contextProvider.setScheme("https");
        contextProvider.setServerName("localhost:8443");
        contextProvider.setContextPath("/");
        contextProvider.setKeyManager(keyManager);

        MetadataCredentialResolver resolver = new MetadataCredentialResolver(cachingMetadataManager, keyManager);
        PKIXTrustEvaluator pkixTrustEvaluator = new CertPathPKIXTrustEvaluator();
        PKIXInformationResolver pkixInformationResolver = new PKIXInformationResolver(resolver, cachingMetadataManager, keyManager);

        contextProvider.setPkixResolver(pkixInformationResolver);
        contextProvider.setPkixTrustEvaluator(pkixTrustEvaluator);
        contextProvider.setMetadataResolver(resolver);

        return contextProvider;
    }
}
