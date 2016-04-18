# git-java-okta-dsl
Okta SAML example with Spring Security

# Usage

1. Add [github gradle plugin](https://github.com/layerhq/gradle-git-repo-plugin) to your `build.gradle`
1. Add `git("https://github.com/jadekler/git-java-okta-dsl", "okta-dsl", "0.0.1", "releases")` to your dependencies

# Running tests

1. Copy `test/resources/credentials.example.yml` to `test/resources/credentials.yml` and fill in appropriately
1. `./gradlew clean test`