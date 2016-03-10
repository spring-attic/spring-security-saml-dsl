# git-java-okta-saml-example
Okta SAML example with Spring Security

## Set up a test okta

1. http://developer.okta.com/
1. TBA

## Running the app

1. `./gradlew clean bootRun`
1. Navigate to `http://localhost:8080`
1. Enter `user` and `password` as account details, and hit Login

## notes to be refactored into instructions

- `keytool -genkey -v -keystore colombia.jks -alias colombia -keyalg RSA -keysize 2048 -validity 10000`