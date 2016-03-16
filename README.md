# git-java-okta-saml-example
Okta SAML example with Spring Security

## Set up a test okta

1. http://developer.okta.com/
1. TBA. Notes:
    - Be sure to 'assign application'
    - Be sure to set the url to 'https://localhost:8443/'

## Running the app

1. `./gradlew clean bootRun`
1. Navigate to `http://localhost:8443`
1. TBC

## notes to be refactored into instructions

- `keytool -genkey -v -keystore colombia.jks -alias colombia -keyalg RSA -keysize 2048 -validity 10000`
