package dev.sigstore.plugin;

//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import static dev.sigstore.ImmutableSigstoreRequest.builder;
import static dev.sigstore.SigstoreRequest.Type.X_509;
import static java.lang.String.format;
import static java.nio.file.Files.copy;
import static java.nio.file.Files.createDirectories;

import dev.sigstore.SigstoreRequest;
import dev.sigstore.SigstoreResult;
import dev.sigstore.SigstoreSigner;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Mojo(name = "sign", threadSafe = true)
public class SignMojo extends AbstractMojo {

  public static final String X509_SIGNATURE_EXTENSION = ".sig";
  public static final String X509_CERTIFICATE_EXTENSION = ".pem";

  private static final Logger logger = LoggerFactory.getLogger(SignMojo.class);

  private final MavenProjectHelper projectHelper;

  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Inject
  public SignMojo(MavenProjectHelper projectHelper) {
    this.projectHelper = projectHelper;
  }

  // ---------------------------------------------------------------------------
  // Sigstore
  // ---------------------------------------------------------------------------

  /**
   * Signing algorithm to be used; default is ECDSA
   */
  @Parameter(defaultValue = "sigstore", property = "signer-name", required = true)
  private String signerName;

  /**
   * Signing algorithm to be used; default is ECDSA
   */
  @Parameter(defaultValue = "EC", property = "signing-algorithm", required = true)
  private String signingAlgorithm;

  /**
   * Signing algorithm specification to be used; default is secp256r1
   */
  @Parameter(defaultValue = "secp256r1", property = "signing-algorithm-spec", required = true)
  private String signingAlgorithmSpec;

  /**
   * URL of Fulcio instance
   */
  @Parameter(defaultValue = "https://fulcio.sigstore.dev", property = "fulcio-instance-url", required = true)
  private URL fulcioInstanceURL;

  /**
   * Use browser-less OAuth Device Code flow instead of opening local browser
   */
  @Parameter(defaultValue = "false", property = "oidc-device-code", required = true)
  private boolean oidcDeviceCodeFlow;

  /**
   * Client ID for OIDC Identity Provider
   */
  @Parameter(defaultValue = "sigstore", property = "oidc-client-id", required = true)
  private String oidcClientID;

  /**
   * URL of OIDC Identity Provider Authorization endpoint
   */
  @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/auth", property = "oidc-auth-url", required = true)
  private URL oidcAuthURL;

  /**
   * URL of OIDC Identity Provider Token endpoint
   */
  @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/token", property = "oidc-token-url", required = true)
  private URL oidcTokenURL;

  /**
   * URL of OIDC Identity Provider Device Code endpoint
   */
  @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/device/code", property = "oidc-device-code-url", required = true)
  private URL oidcDeviceCodeURL;

  /**
   * URL of Rekor instance
   */
  @Parameter(defaultValue = "https://rekor.sigstore.dev", property = "rekor-instance-url", required = true)
  private URL rekorInstanceURL;

  /**
   * Email address of signer; if not specified, the email address returned in the OIDC identity token will be used
   */
  @Parameter(property = "emailAddress")
  private String emailAddress;

  /**
   * URL of Trusted Timestamp Authority (RFC3161 compliant)
   */
  @Parameter(defaultValue = "https://rekor.sigstore.dev/api/v1/timestamp", property = "tsa-url", required = true)
  private URL tsaURL;

  @Override
  public void execute() throws MojoExecutionException {
    List<SignedFile> mavenFilesToSign = new ArrayList<>();
    if (!"pom".equals(project.getPackaging())) {
      //
      // Primary artifact
      //
      org.apache.maven.artifact.Artifact artifact = project.getArtifact();
      File file = artifact.getFile();
      if (file == null) {
        logger.info("There is no artifact present. Make sure you run this after the package phase.");
        return;
      }
      mavenFilesToSign.add(new SignedFile(file.toPath(), artifact.getArtifactHandler().getExtension()));
    }

    //
    // POM
    //
    File pomToSign = new File(project.getBuild().getDirectory(), project.getBuild().getFinalName() + ".pom");
    try {
      createDirectories(pomToSign.getParentFile().toPath());
      copy(project.getFile().toPath(), pomToSign.toPath(), StandardCopyOption.REPLACE_EXISTING);
      mavenFilesToSign.add(new SignedFile(pomToSign.toPath(), "pom"));
    } catch (IOException e) {
      throw new MojoExecutionException("Error copying POM for signing.", e);
    }

    //
    // Attached artifacts
    //
    for (org.apache.maven.artifact.Artifact a : project.getAttachedArtifacts()) {
      mavenFilesToSign.add(new SignedFile(a.getFile().toPath(), a.getArtifactHandler().getExtension(), a.getClassifier()));
    }

    // We have an example build that we use for testing here: https://github.com/jvanzyl/maven-sigstore-test
    //
    // The comments and notes below are an illustration of the signing process with this project.
    //
    // These are the Maven produced files to be signed with sigstore:
    //
    // maven-sigstore-test-{{version}}.jar
    // maven-sigstore-test-{{version}}.pom
    // maven-sigstore-test-{{version}}-sources.jar

    KeyPair keyPair = null;
    CertPath fulcioSigningCert = null;
    logger.debug("Signing the following files sigstore:");
    mavenFilesToSign.forEach(s -> logger.debug(s.toString()));
    List<SignedFile> filesToSignWithPgp = new ArrayList<>();
    for (SignedFile mavenFileToSign : mavenFilesToSign) {
      Path file = mavenFileToSign.file();
      try {
        SigstoreRequest request = builder()
            .keyPair(keyPair)
            .signingCert(fulcioSigningCert)
            .artifact(file)
            .type(X_509)
            .build();
        // The Maven file we pass along to be signed with PGP
        SigstoreResult result = new SigstoreSigner(request).sign();
        filesToSignWithPgp.add(mavenFileToSign);
        // The sigstore .sig file
        projectHelper.attachArtifact(project, mavenFileToSign.extension() + X509_SIGNATURE_EXTENSION, mavenFileToSign.classifier(), result.artifactSignature().toFile());
        filesToSignWithPgp.add(new SignedFile(request.artifactSignature(), mavenFileToSign.extension() + X509_SIGNATURE_EXTENSION, mavenFileToSign.classifier()));
        // The sigstore .pem file
        projectHelper.attachArtifact(project, mavenFileToSign.extension() + X509_CERTIFICATE_EXTENSION, mavenFileToSign.classifier(), result.signingCertificate().toFile());
        filesToSignWithPgp.add(new SignedFile(request.outputSigningCert(), mavenFileToSign.extension() + X509_CERTIFICATE_EXTENSION, mavenFileToSign.classifier()));
        // Let's hold on the signing certificate and reuse as long as we can
        keyPair = result.keyPair();
        fulcioSigningCert = result.signingCert();
      } catch (Exception e) {
        throw new MojoExecutionException(format("Error signing Maven file %s with Sigstore.", mavenFileToSign), e);
      }
    }
  }
}
