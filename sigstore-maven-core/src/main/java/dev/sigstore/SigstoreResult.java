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
import java.util.Map;
import javax.annotation.Nullable;
import org.immutables.value.Value;

@Value.Immutable
public abstract class SigstoreResult {

  @Nullable
  public abstract Path artifactSignature();

  @Nullable
  public abstract Path signingCertificate();

  @Nullable
  public abstract String emailAddress();

  @Nullable
  public abstract String signedEmailAddress();

  @Nullable
  public abstract String rawIdToken();

  @Nullable
  public abstract KeyPair keyPair();

  @Nullable
  public abstract String artifactSignatureContent(); // b64

  @Nullable
  public abstract CertPath signingCert(); //fulcioSigningCertificate

  @Nullable
  public abstract String publicKeyContent();

  @Nullable
  public abstract Path publicKeyPath();

  @Nullable
  public abstract Map<String, Object> rekorRecord();

  @Nullable
  public abstract String rekorEntryUrl();
}