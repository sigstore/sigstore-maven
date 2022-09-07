package dev.sigstore;

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

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertPath;
import javax.annotation.Nullable;
import org.immutables.value.Value;

@Value.Immutable
public abstract class SigstoreRequest {

  public abstract Type type();

  @Nullable
  public abstract Path artifact();

  @Value.Derived
  public Path artifactSignature() {
    return artifact().resolveSibling(artifact().getFileName().toString() + ".sig");
  }

  @Value.Derived
  public Path outputSigningCert() {
    return artifact().resolveSibling(artifact().getFileName().toString() + ".pem");
  }

  @Value.Default
  public String signerName() {
    return "sigstore";
  }

  @Value.Default
  public String signingAlgorithm() {
    return "EC";
  }

  @Value.Default
  public String signingAlgorithmSpec() {
    return "secp256r1";
  }

  @Value.Default
  public boolean sslVerfication() {
    return true;
  }

  @Nullable
  public abstract CertPath signingCert();

  @Nullable
  public abstract KeyPair keyPair();

  @Value.Default
  public String fulcioInstanceURL() {
    return "https://fulcio.sigstore.dev";
  }

  @Value.Default
  public boolean oidcDeviceCodeFlow() {
    return false;
  }

  @Value.Default
  public String oidcClientID() {
    return "sigstore";
  }

  @Value.Default
  public String oidcAuthURL() {
    return "https://oauth2.sigstore.dev/auth/auth";
  }

  @Value.Default
  public String oidcTokenURL() {
    return "https://oauth2.sigstore.dev/auth/token";
  }

  @Value.Default
  public String oidcDeviceCodeURL() {
    return "https://oauth2.sigstore.dev/auth/device/code";
  }

  @Value.Default
  public String rekorInstanceURL() {
    return "https://rekor.sigstore.dev";
  }

  @Nullable
  public abstract String emailAddress();

  @Value.Default
  public String tsaURL() {
    return "https://rekor.sigstore.dev/api/v1/timestamp";
  }

  public enum Type {
    X_509("x509");
    private final String value;
    Type(String value) {
      this.value = value;
    }
  }
}
