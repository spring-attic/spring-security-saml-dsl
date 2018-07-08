package org.springframework.security.extensions.saml2.config;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

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

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.storage.SAMLMessageStorageFactory;
import org.springframework.security.saml.trust.MetadataCredentialResolver;
import org.springframework.security.saml.trust.PKIXInformationResolver;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/*
 Spring security configurer for okta.
 @Author Mark Douglass
 @Author Jean de Klerk
*/
public class SAMLConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	private static final RequestHeaderRequestMatcher X_REQUESTED_WITH = new RequestHeaderRequestMatcher("X-Requested-With",
			"XMLHttpRequest");

	private IdentityProvider identityProvider = new IdentityProvider();
	private ServiceProvider serviceProvider = new ServiceProvider();
	private WebSSOProfileConsumerImpl webSSOProfileConsumer = new WebSSOProfileConsumerImpl();
	private StaticBasicParserPool parserPool = staticBasicParserPool();
	private SAMLProcessor samlProcessor = samlProcessor();
	private SAMLDefaultLogger samlLogger = new SAMLDefaultLogger();

	private WebSSOProfileOptions webSSOProfileOptions;
	private MetadataProvider metadataProvider;
	private ExtendedMetadataDelegate extendedMetadataDelegate;
	private CachingMetadataManager cachingMetadataManager;
	private WebSSOProfile webSSOProfile;
	private SingleLogoutProfile singleLogoutProfile;
	private SAMLAuthenticationProvider samlAuthenticationProvider;

	private SAMLUserDetailsService samlUserDetailsService;
	private boolean forcePrincipalAsString = false;
	private AuthenticationSuccessHandler successHandler;
	private AuthenticationFailureHandler failureHandler;
	private LogoutSuccessHandler logoutSuccessHandler = defaultLogoutSuccessHandler();
	private ApplicationEventPublisher applicationEventPublisher;
	private AuthenticationEntryPoint xmlHttpRequestedWithEntryPoint = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);
	private Collection<String> defaultAuthnContexts;
	private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
		public <T> T postProcess(T object) {
			return object;
		}
	};


	private SAMLConfigurer() {
	}

	@Override
	public void init(HttpSecurity http) throws Exception {
		webSSOProfileOptions = webSSOProfileOptions();
		metadataProvider = identityProvider.metadataProvider();
		ExtendedMetadata extendedMetadata = extendedMetadata(identityProvider.discoveryEnabled);
		extendedMetadataDelegate = extendedMetadataDelegate(extendedMetadata);
		serviceProvider.keyManager = serviceProvider.keyManager();
		cachingMetadataManager = cachingMetadataManager();
		webSSOProfile = new WebSSOProfileImpl(samlProcessor, cachingMetadataManager);
		singleLogoutProfile = singleLogoutProfile();
		samlAuthenticationProvider = samlAuthenticationProvider(webSSOProfileConsumer);

		bootstrap();

		SAMLContextProvider contextProvider = contextProvider();
		SAMLEntryPoint samlEntryPoint = samlEntryPoint(contextProvider);

		http.httpBasic().authenticationEntryPoint(prepareEntryPoint(samlEntryPoint));

		CsrfConfigurer<HttpSecurity> csrfConfigurer = http.getConfigurer(CsrfConfigurer.class);
		if (csrfConfigurer != null) {
			disableCsrfForSamlEndpoints(csrfConfigurer);
		}

		http
				.addFilterBefore(metadataGeneratorFilter(samlEntryPoint, extendedMetadata), ChannelProcessingFilter.class)
				.addFilterAfter(samlFilter(samlEntryPoint, contextProvider), BasicAuthenticationFilter.class)
				.authenticationProvider(samlAuthenticationProvider);
	}

	public static SAMLConfigurer saml() {
		return new SAMLConfigurer();
	}

	public SAMLConfigurer userDetailsService(SAMLUserDetailsService samlUserDetailsService) {
		this.samlUserDetailsService = samlUserDetailsService;
		return this;
	}

	public SAMLConfigurer forcePrincipalAsString() {
		this.forcePrincipalAsString = true;
		return this;
	}

	public SAMLConfigurer webSSOProfileConsumer(WebSSOProfileConsumerImpl webSSOProfileConsumer) {
		this.webSSOProfileConsumer = webSSOProfileConsumer;
		return this;
	}

	public SAMLConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
		this.successHandler = successHandler;
		return this;
	}

	public SAMLConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
		this.failureHandler = failureHandler;
		return this;
	}

	public SAMLConfigurer logoutHandler(LogoutSuccessHandler logoutSuccessHandler) {
		Assert.notNull(logoutSuccessHandler, "LogoutSuccessHandler must not be null");
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	public SAMLConfigurer applicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.applicationEventPublisher = applicationEventPublisher;
		return this;
	}

	public SAMLConfigurer xmlHttpRequestedWithEntryPoint(AuthenticationEntryPoint xmlHttpRequestedWithEntryPoint) {
		this.xmlHttpRequestedWithEntryPoint = xmlHttpRequestedWithEntryPoint;
		return this;
	}

	public SAMLConfigurer defaultAuthnContexts(Collection<String> defaultAuthnContexts) {
		this.defaultAuthnContexts = defaultAuthnContexts;
		return this;
	}

	public IdentityProvider identityProvider() {
		return identityProvider;
	}

	public ServiceProvider serviceProvider() {
		return serviceProvider;
	}

	private String entityBaseURL() {
		String entityBaseURL = serviceProvider.hostName + "/" + serviceProvider.basePath;
		entityBaseURL = entityBaseURL.replaceAll("//", "/").replaceAll("/$", "");
		entityBaseURL = serviceProvider.protocol + "://" + entityBaseURL;
		return entityBaseURL;
	}

	private AuthenticationEntryPoint prepareEntryPoint(SAMLEntryPoint samlEntryPoint) {
		if (this.xmlHttpRequestedWithEntryPoint != null) {
			LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
			entryPoints.put(X_REQUESTED_WITH, this.xmlHttpRequestedWithEntryPoint);
			DelegatingAuthenticationEntryPoint defaultEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
			defaultEntryPoint.setDefaultEntryPoint(samlEntryPoint);
			return defaultEntryPoint;
		}
		return samlEntryPoint;
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

	private SecurityContextLogoutHandler logoutHandler() {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setInvalidateHttpSession(true);
		logoutHandler.setClearAuthentication(true);
		return logoutHandler;
	}

	private SAMLLogoutFilter samlLogoutFilter(SAMLContextProvider contextProvider) {
		SAMLLogoutFilter samlLogoutFilter = new SAMLLogoutFilter(this.logoutSuccessHandler,
				new LogoutHandler[] {logoutHandler()},
				new LogoutHandler[] {logoutHandler()});
		samlLogoutFilter.setProfile(singleLogoutProfile);
		samlLogoutFilter.setContextProvider(contextProvider);
		samlLogoutFilter.setSamlLogger(samlLogger);
		return samlLogoutFilter;
	}

	private SAMLLogoutProcessingFilter samlLogoutProcessingFilter(SAMLContextProvider contextProvider) {
		SAMLLogoutProcessingFilter samlLogoutProcessingFilter =
				new SAMLLogoutProcessingFilter(this.logoutSuccessHandler, logoutHandler());
		samlLogoutProcessingFilter.setLogoutProfile(singleLogoutProfile);
		samlLogoutProcessingFilter.setContextProvider(contextProvider);
		samlLogoutProcessingFilter.setSamlLogger(samlLogger);
		samlLogoutProcessingFilter.setSAMLProcessor(samlProcessor);
		return samlLogoutProcessingFilter;
	}

	private SAMLProcessor samlProcessor() {
		Collection<SAMLBinding> bindings = new ArrayList<>();
		bindings.add(httpRedirectDeflateBinding(parserPool));
		bindings.add(httpPostBinding(parserPool));
		return new SAMLProcessorImpl(bindings);
	}

	private CachingMetadataManager cachingMetadataManager() throws MetadataProviderException {
		List<MetadataProvider> providers = new ArrayList<>();
		providers.add(extendedMetadataDelegate);
		CachingMetadataManager cachingMetadataManager = new CachingMetadataManager(providers);
		cachingMetadataManager.setKeyManager(serviceProvider.keyManager);
		return cachingMetadataManager;
	}

	private StaticBasicParserPool staticBasicParserPool() {
		StaticBasicParserPool parserPool = new StaticBasicParserPool();
		try {
			parserPool.initialize();
		} catch (XMLParserException e) {
			throw new RuntimeException("Could not initialize StaticBasicParserPool", e);
		}
		return parserPool;
	}

	private ExtendedMetadataDelegate extendedMetadataDelegate(ExtendedMetadata extendedMetadata) {
		ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(metadataProvider, extendedMetadata);
		extendedMetadataDelegate.setMetadataTrustCheck(false);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		return extendedMetadataDelegate;
	}

	private ExtendedMetadata extendedMetadata(boolean discoveryEnabled) {
		ExtendedMetadata extendedMetadata = new ExtendedMetadata();
		extendedMetadata.setIdpDiscoveryEnabled(discoveryEnabled);
		extendedMetadata.setSignMetadata(true);
		return extendedMetadata;
	}

	private WebSSOProfileOptions webSSOProfileOptions() {
		WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
		webSSOProfileOptions.setIncludeScoping(false);
		if (this.defaultAuthnContexts != null && !this.defaultAuthnContexts.isEmpty()) {
			webSSOProfileOptions.setAuthnContexts(defaultAuthnContexts);
		}
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

	private SAMLProcessingFilter samlWebSSOProcessingFilter(SAMLContextProvider contextProvider) throws Exception {
		SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();

		samlWebSSOProcessingFilter.setAuthenticationManager(this.authenticationManager(samlAuthenticationProvider));
		samlWebSSOProcessingFilter.setContextProvider(contextProvider);
		samlWebSSOProcessingFilter.setSAMLProcessor(samlProcessor);
		if (this.successHandler != null) {
			samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(this.successHandler);
		}
		if (this.failureHandler != null) {
			samlWebSSOProcessingFilter.setAuthenticationFailureHandler(this.failureHandler);
		}
		if (this.applicationEventPublisher != null) {
			samlWebSSOProcessingFilter.setApplicationEventPublisher(this.applicationEventPublisher);
		}
		return samlWebSSOProcessingFilter;
	}

	private AuthenticationManager authenticationManager(SAMLAuthenticationProvider samlAuthenticationProvider) throws Exception {
		AuthenticationManagerBuilder authenticationManagerBuilder = new AuthenticationManagerBuilder(this.objectPostProcessor);
		authenticationManagerBuilder.authenticationProvider(samlAuthenticationProvider);
		if (this.applicationEventPublisher != null) {
			DefaultAuthenticationEventPublisher authenticationEventPublisher = new DefaultAuthenticationEventPublisher();
			authenticationEventPublisher.setApplicationEventPublisher(this.applicationEventPublisher);
			authenticationManagerBuilder.authenticationEventPublisher(authenticationEventPublisher);
		}
		return authenticationManagerBuilder.build();
	}

	private MetadataGeneratorFilter metadataGeneratorFilter(SAMLEntryPoint samlEntryPoint, ExtendedMetadata extendedMetadata) {
		MetadataGeneratorFilter metadataGeneratorFilter = new MetadataGeneratorFilter(getMetadataGenerator(samlEntryPoint, extendedMetadata));
		metadataGeneratorFilter.setManager(cachingMetadataManager);
		return metadataGeneratorFilter;
	}

	private FilterChainProxy samlFilter(SAMLEntryPoint samlEntryPoint, SAMLContextProvider contextProvider) throws Exception {
		List<SecurityFilterChain> chains = new ArrayList<>();
		chains.add(securityFilterChain("/saml/login/**", samlEntryPoint));
		chains.add(securityFilterChain("/saml/logout/**", samlLogoutFilter(contextProvider)));
		chains.add(securityFilterChain("/saml/metadata/**", metadataDisplayFilter(contextProvider)));
		chains.add(securityFilterChain("/saml/SSO/**", samlWebSSOProcessingFilter(contextProvider)));
		chains.add(securityFilterChain("/saml/SingleLogout/**", samlLogoutProcessingFilter(contextProvider)));
		chains.add(securityFilterChain("/saml/discovery/**", samlDiscovery(contextProvider)));

		return new FilterChainProxy(chains);
	}

	private static DefaultSecurityFilterChain securityFilterChain(String pattern, Filter filter) {
		return new DefaultSecurityFilterChain(new AntPathRequestMatcher(pattern), filter);
	}

	private SAMLDiscovery samlDiscovery(SAMLContextProvider contextProvider) {
		SAMLDiscovery samlDiscovery = new SAMLDiscovery();
		samlDiscovery.setMetadata(cachingMetadataManager);
		samlDiscovery.setContextProvider(contextProvider);
		return samlDiscovery;
	}

	private MetadataDisplayFilter metadataDisplayFilter(SAMLContextProvider contextProvider) {
		MetadataDisplayFilter metadataDisplayFilter = new MetadataDisplayFilter();
		metadataDisplayFilter.setContextProvider(contextProvider);
		metadataDisplayFilter.setManager(cachingMetadataManager);
		metadataDisplayFilter.setKeyManager(serviceProvider.keyManager);
		return metadataDisplayFilter;
	}

	private SingleLogoutProfile singleLogoutProfile() {
		SingleLogoutProfileImpl singleLogoutProfile = new SingleLogoutProfileImpl();
		singleLogoutProfile.setMetadata(cachingMetadataManager);
		singleLogoutProfile.setProcessor(samlProcessor);
		return singleLogoutProfile;
	}

	private SAMLAuthenticationProvider samlAuthenticationProvider(WebSSOProfileConsumerImpl webSSOProfileConsumer) {
		SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
		samlAuthenticationProvider.setForcePrincipalAsString(forcePrincipalAsString);
		samlAuthenticationProvider.setSamlLogger(samlLogger);
		samlAuthenticationProvider.setConsumer(webSSOProfileConsumer);
		samlAuthenticationProvider.setUserDetails(this.samlUserDetailsService);
		samlAuthenticationProvider.setExcludeCredential(serviceProvider.excludeCredential);
		return samlAuthenticationProvider;
	}

	private SAMLContextProvider contextProvider() {
		SAMLContextProviderLB contextProvider = new SAMLContextProviderLB();
		contextProvider.setMetadata(cachingMetadataManager);
		contextProvider.setScheme(serviceProvider.protocol);
		contextProvider.setServerName(serviceProvider.hostName);
		contextProvider.setContextPath(serviceProvider.basePath);
		contextProvider.setKeyManager(serviceProvider.keyManager);

		MetadataCredentialResolver resolver = new MetadataCredentialResolver(cachingMetadataManager, serviceProvider.keyManager);
		PKIXTrustEvaluator pkixTrustEvaluator = new CertPathPKIXTrustEvaluator();
		PKIXInformationResolver pkixInformationResolver = new PKIXInformationResolver(resolver, cachingMetadataManager, serviceProvider.keyManager);

		contextProvider.setPkixResolver(pkixInformationResolver);
		contextProvider.setPkixTrustEvaluator(pkixTrustEvaluator);
		contextProvider.setMetadataResolver(resolver);

		if (serviceProvider.storageFactory != null) {
			contextProvider.setStorageFactory(serviceProvider.storageFactory);
		}

		return contextProvider;
	}

	private MetadataGenerator getMetadataGenerator(SAMLEntryPoint samlEntryPoint, ExtendedMetadata extendedMetadata) {
		MetadataGenerator metadataGenerator = new MetadataGenerator();

		metadataGenerator.setSamlEntryPoint(samlEntryPoint);
		metadataGenerator.setEntityBaseURL(entityBaseURL());
		metadataGenerator.setKeyManager(serviceProvider.keyManager);
		metadataGenerator.setEntityId(serviceProvider.entityId);
		metadataGenerator.setIncludeDiscoveryExtension(false);
		metadataGenerator.setExtendedMetadata(extendedMetadata);

		return metadataGenerator;
	}

	private SimpleUrlLogoutSuccessHandler defaultLogoutSuccessHandler() {
		SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
		logoutSuccessHandler.setDefaultTargetUrl("/");

		return logoutSuccessHandler;
	}

	public class IdentityProvider {

		private String metadataFilePath;

		private boolean discoveryEnabled = true;

		public IdentityProvider metadataFilePath(String metadataFilePath) {
			this.metadataFilePath = metadataFilePath;
			return this;
		}

		public IdentityProvider discoveryEnabled(boolean discoveryEnabled) {
			this.discoveryEnabled = discoveryEnabled;
			return this;
		}

		private MetadataProvider metadataProvider() throws MetadataProviderException, IOException {
			if (metadataFilePath.startsWith("http")) {
				return httpMetadataProvider();
			} else {
				return fileSystemMetadataProvider();
			}
		}

		private HTTPMetadataProvider httpMetadataProvider() throws MetadataProviderException {
			HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(new Timer(), new HttpClient(), metadataFilePath);
			httpMetadataProvider.setParserPool(parserPool);
			return httpMetadataProvider;
		}

		private FilesystemMetadataProvider fileSystemMetadataProvider() throws IOException, MetadataProviderException {
			DefaultResourceLoader loader = new DefaultResourceLoader();
			Resource metadataResource = loader.getResource(metadataFilePath);
			File samlMetadata = metadataResource.getFile();
			FilesystemMetadataProvider filesystemMetadataProvider = new FilesystemMetadataProvider(samlMetadata);
			filesystemMetadataProvider.setParserPool(parserPool);
			return filesystemMetadataProvider;
		}

		public SAMLConfigurer and() {
			return SAMLConfigurer.this;
		}

	}

	private void disableCsrfForSamlEndpoints(CsrfConfigurer<HttpSecurity> csrfConfigurer) {
		// Workaround to get working with Spring Security 3.2.
		RequestMatcher ignored = new AntPathRequestMatcher("/saml/**");
		RequestMatcher notIgnored = new NegatedRequestMatcher(ignored);
		RequestMatcher matcher = new AndRequestMatcher(new DefaultRequiresCsrfMatcher(), notIgnored);

		csrfConfigurer.requireCsrfProtectionMatcher(matcher);
	}

	public class ServiceProvider {

		private KeyStore keyStore = new KeyStore();

		private KeyManager keyManager;

		private String protocol;

		private String hostName;

		private String basePath;

		private String entityId;

		private SAMLMessageStorageFactory storageFactory;

		private boolean excludeCredential = false;

		public ServiceProvider protocol(String protocol) {
			this.protocol = protocol;
			return this;
		}

		public ServiceProvider hostname(String hostname) {
			this.hostName = hostname;
			return this;
		}

		public ServiceProvider basePath(String basePath) {
			this.basePath = basePath;
			return this;
		}

		public ServiceProvider entityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		public ServiceProvider storageFactory(SAMLMessageStorageFactory storageFactory) {
			this.storageFactory = storageFactory;
			return this;
		}

		public ServiceProvider excludeCredential(boolean excludeCredential) {
			this.excludeCredential = excludeCredential;
			return this;
		}

		public KeyStore keyStore() {
			return keyStore;
		}

		public SAMLConfigurer and() {
			return SAMLConfigurer.this;
		}

		private KeyManager keyManager() throws IOException {
			DefaultResourceLoader loader = new DefaultResourceLoader();
			Resource storeFile = loader.getResource(keyStore.getStoreFilePath());
			if (keyStore.getStoreFilePath().startsWith("file://")) {
				storeFile = new FileSystemResource(storeFile.getFile());
			}
			Map<String, String> passwords = new HashMap<>();
			passwords.put(keyStore.getKeyname(), keyStore.getKeyPassword());
			return new JKSKeyManager(storeFile, keyStore.getPassword(), passwords, keyStore.getKeyname());
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

			public ServiceProvider and() {
				return ServiceProvider.this;
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
		}
	}

	final class DefaultRequiresCsrfMatcher implements RequestMatcher {
		private Pattern allowedMethods = Pattern.compile("^(GET|HEAD|TRACE|OPTIONS)$");

		/* (non-Javadoc)
		 * @see org.springframework.security.web.util.matcher.RequestMatcher#matches(javax.servlet.http.HttpServletRequest)
		 */
		public boolean matches(HttpServletRequest request) {
			return !allowedMethods.matcher(request.getMethod()).matches();
		}
	}

}
