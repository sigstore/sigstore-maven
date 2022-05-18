# Maven Sigstore

This repository currently houses three modules to support Sigstore keyless signing with Maven. It's a work in progress, and much of what is currently here will collapse into the [Sigstore Java][1] project. What will be left here, eventually, is the `sigstore-maven-plugin`. We are looking for OSS projects using Maven to try out this integration, and we hope to have a first public release in June 2022.

## Questions

- How does the Java ecosystem gracefully transition to keyless signing?
- How to deal with non-interactive builds?
- How to deal with builds that take longer than the expiry window of the Fulcio x509 certificates?
- Should we use `.crt` for the certificate? (Michael Osipov)
  - https://datatracker.ietf.org/doc/html/rfc7468#section-5.3
  - https://datatracker.ietf.org/doc/html/rfc7468#section-1
- How do we address cryptography vulnerabilities in the JDK?
  - [Psychic Signatures](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java)
- Do we need a piece of metadata to at least describe a revision of the layout? So that tooling that might process all the entries can know about different versions along the way and deal with them accordingly if issue are found retroactively.

## Process of generating signatures

To start we have a typical Maven build that has a `pom.xml`, and the build produces a binary JAR with an accompanying source JAR:

```
maven-sigstore-test-{{version}}.jar
maven-sigstore-test-{{version}}.pom
maven-sigstore-test-{{version}}-sources.jar
```

For each Maven file to be deployed to a remote repository, there will be an accompanying x509 certificate and signature that will also be deployed:

```
maven-sigstore-test-{{version}}.jar
maven-sigstore-test-{{version}}.jar.sig
maven-sigstore-test-{{version}}.jar.pem
maven-sigstore-test-{{version}}.pom
maven-sigstore-test-{{version}}.pom.sig
maven-sigstore-test-{{version}}.pom.pem
maven-sigstore-test-{{version}}-sources.jar
maven-sigstore-test-{{version}}-sources.jar.sig
maven-sigstore-test-{{version}}-sources.jar.pem
```

At some point in the future the above list is all we will need, but at this point in time (May 2022) developers in the Java ecosystem are accustomed to signing Maven files with PGP keys and Maven Central requires them. So for each of the files we have above, we must sign them all with a PGP key in order for Maven Central signature validation to pass. So what we have to be deployed to Maven Central is the following:

```
maven-sigstore-test-{{version}}.jar
maven-sigstore-test-{{version}}.jar.asc
maven-sigstore-test-{{version}}.jar.sig
maven-sigstore-test-{{version}}.jar.sig.asc
maven-sigstore-test-{{version}}.jar.pem
maven-sigstore-test-{{version}}.jar.pem.asc
maven-sigstore-test-{{version}}.pom
maven-sigstore-test-{{version}}.pom.asc
maven-sigstore-test-{{version}}.pom.sig
maven-sigstore-test-{{version}}.pom.sig.asc
maven-sigstore-test-{{version}}.pom.pem
maven-sigstore-test-{{version}}.pom.pem.asc
maven-sigstore-test-{{version}}-sources.jar
maven-sigstore-test-{{version}}-sources.jar.asc
maven-sigstore-test-{{version}}-sources.jar.sig
maven-sigstore-test-{{version}}-sources.jar.sig.asc
maven-sigstore-test-{{version}}-sources.jar.pem
maven-sigstore-test-{{version}}-sources.jar.pem.asc
```

A rather long list of files for a simple deployment to Maven Central, but not the end of the world. As the Sigstore verification mechanisms are built into Maven Central the generation of PGP signatures can be shed.

## Notes

- [Zero-friction “keyless signing” with Github Actions](https://blog.chainguard.dev/zero-friction-keyless-signing-with-github-actions/)
- [Everything you should know about certificates and PKI but are too afraid to ask (Mike Malone: 2018-12-11)](https://smallstep.com/blog/everything-pki/)
- [Transparent Logs for Skeptical Clients (Russ Cox: 2019-03-01)](https://research.swtch.com/tlog)
- [The OpenSSH Private Key Format (AJ ONeal: 2018-12-5)](https://coolaj86.com/articles/the-openssh-private-key-format/)
- [About security hardening with OpenID Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Digital Signatures Using Java](https://www.veracode.com/blog/research/digital-signatures-using-java)

[1]: https://github.com/sigstore/sigstore-java
