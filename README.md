# spring-security-saml-dsl


## Usage

### Gradle

#### Milestone

You can find the latest milestone in the [Spring Milestone repository](https://repo.spring.io/libs-milestone/org/springframework/security/extensions/spring-security-saml-dsl/) Below is an example using M3.

```groovy
repositories {
	maven {
		url 'https://repo.spring.io/libs-milestone'
	}
}
dependencies {
	compile 'org.springframework.security.extensions:spring-security-saml-dsl:1.0.0.M3'
}
```


#### Snapshot

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

#### Milestone

You can find the latest milestone in the [Spring Milestone repository](https://repo.spring.io/libs-milestone/org/springframework/security/extensions/spring-security-saml-dsl/) Below is an example using M3.

```xml
<dependencies>
	<dependency>
		<groupId>org.springframework.security.extensions</groupId>
		<artifactId>spring-security-saml-dsl</artifactId>
		<version>1.0.0.M3</version>
	</dependency>
</dependencies>
<repositories>
	<repository>
		<id>spring-snapshots</id>
		<name>Spring Snapshots</name>
		<url>https://repo.spring.io/libs-milestone</url>
	</repository>
</repositories>
```

#### Snapshot

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
