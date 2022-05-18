package dev.sigstore.x509;

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

import static dev.sigstore.SigstoreRequest.Type.X_509;
import static org.assertj.core.api.Assertions.assertThat;

import dev.sigstore.SigstoreRequest;
import dev.sigstore.SigstoreResult;
import dev.sigstore.SigstoreSigner;
import dev.sigstore.SigstoreTestSupport;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.util.List;
import org.junit.Ignore;
import org.junit.Test;

public class X509ProcessorTest extends SigstoreTestSupport {

  @Test
  @Ignore
  public void validateSigning() throws Exception {
    KeyPair keyPair = null;
    CertPath fulcioSigningCert = null;
    for(String artifactName : List.of("test0", "test1")) {
      System.out.println("!!! ------------------------------------------------------------------");
      System.out.println("!!! Signing " + artifactName);
      System.out.println("!!! ------------------------------------------------------------------");
      Path artifact = jarArtifact(artifactName);
      SigstoreRequest request = localRequestBuilder()
          .keyPair(keyPair)
          .signingCert(fulcioSigningCert)
          .type(X_509)
          .artifact(artifact)
          .build();
      SigstoreSigner signer = new SigstoreSigner(request);
      SigstoreResult result = signer.sign();
      keyPair = result.keyPair();
      fulcioSigningCert = result.signingCert();
      assertThat(keyPair).isNotNull();
      assertThat(fulcioSigningCert).isNotNull();
      assertThat(result.signingCertificate()).isNotNull();
      assertThat(result.artifactSignature()).isNotNull();
    }
  }
}
