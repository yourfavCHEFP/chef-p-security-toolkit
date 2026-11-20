# Java / Kotlin
Manifests: `pom.xml`, `build.gradle(.kts)`. Tests: `mvn -q test` or `./gradlew test`. Audit: osv-scanner, trivy (OWASP Dependency-Check is a common alternative).
Upgrade: bump the version property/dependency; for transitive pins use `dependencyManagement` (Maven) or `constraints` (Gradle). Watch for `ObjectInputStream`, string-built SQL, XXE in XML parsers.
