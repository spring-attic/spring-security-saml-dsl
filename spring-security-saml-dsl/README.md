## Running tests

1. Copy `test/resources/credentials.example.yml` to `test/resources/credentials.yml` and fill in with the correct test credentials.
1. Replace your saml metadata.xml with your test IDP metadata.
1. Update application-http-metadata.yml with the path or url of metadata.xml
1. `./gradlew clean test`