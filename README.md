# spring-security-saml-dsl


## Usage

### Gradle

```groovy
repositories {
	maven {
		url 'https://repo.spring.io/libs-snapshot'
	}
}
dependencies {
	compile 'org.springframework.security.extensions:spring-security-saml-dsl:1.0.0.BUILD-SNAPSHOT'
}
```


### Maven

```xml
<dependencies>
	<dependency>
		<groupId>org.springframework.security.extensions</groupId>
		<artifactId>spring-security-saml-dsl</artifactId>
		<version>1.0.0.BUILD-SNAPSHOT</version>
	</dependency>
</dependencies>
<repositories>
	<repository>
		<id>spring-snapshots</id>
		<name>Spring Snapshots</name>
		<url>https://repo.spring.io/libs-snapshot</url>
		<snapshots>
			<enabled>true</enabled>
		</snapshots>
	</repository>
</repositories>
```

## Example usage

Navigate to [samples/spring-security-saml-dsl-sample](https://github.com/jadekler/spring-security-saml-dsl/tree/master/samples/spring-security-saml-dsl-sample)
for a complete README on setting up okta and configuring your app with the DSL to point at okta.

## Contributing
[Pull requests](https://help.github.com/articles/using-pull-requests/) are welcome; see the [contributor guidelines](https://github.com/spring-projects/spring-framework/blob/master/CONTRIBUTING.md) for details.