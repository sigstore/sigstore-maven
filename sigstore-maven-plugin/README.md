# Sigstore Maven Plugin

A Maven plugin that can be used for keyless Sigstore signing. This plugin also attempts to make the transition away from PGP signing easier.

## All signing mode

In this mode, you disable any PGP signing you have in your current build, and let the `sigstore-maven-plugin` do the PGP signing along with the Sigstore signing. The PGP implementation in the plugin doesn't require the GPG executable on your machine, and in default mode it will use the default key in your local keyring. In this way the management of shedding PGP signing can be managed in one place.

```xml
<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>io.takari</groupId>
    <artifactId>takari</artifactId>
    <version>48</version>
  </parent>
  <groupId>ca.vanzyl</groupId>
  <artifactId>maven-sigstore-test</artifactId>
  <version>0.0.21-SNAPSHOT</version>
  <packaging>takari-jar</packaging>

  <profiles>
    <profile>
      <id>takari-release</id>
      <properties>
        <takari.release.gpg.skip>true</takari.release.gpg.skip>
      </properties>
      <build>
        <plugins>
          <plugin>
            <groupId>dev.sigstore.maven.plugins</groupId>
            <artifactId>sigstore-maven-plugin</artifactId>
            <version>0.0.17</version>
            <executions>
              <execution>
                <configuration>
                  <mavenPgpSignatures>true</mavenPgpSignatures>
                </configuration>
                <goals>
                  <goal>sign</goal>
                </goals>
              </execution>
            </executions>
          </plugin>
        </plugins>
      </build>
    </profile>
  </profiles>
</project>
```

When the release is made to Maven Central it will have all the necessary signatures, and for the time being the Sigstore signatures are signed with PGP to allow this hybrid mode of signing to work with no changes required in Maven Central.

For a working example of how to use this plugin you can refer to https://github.com/jvanzyl/maven-sigstore-test
