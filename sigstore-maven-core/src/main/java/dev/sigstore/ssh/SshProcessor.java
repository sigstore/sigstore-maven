package dev.sigstore.ssh;

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

import static dev.sigstore.ImmutableSigstoreResult.Builder;
import static dev.sigstore.ImmutableSigstoreResult.builder;
import static dev.sigstore.SigstoreSigner.base64;
import static dev.sigstore.SigstoreSigner.sha256;
import static java.nio.file.Files.writeString;

import dev.sigstore.SigstoreProcessorSupport;
import dev.sigstore.SigstoreRequest;
import dev.sigstore.SigstoreResult;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.util.io.pem.PemReader;

// https://stackoverflow.com/questions/66476780/sign-verify-json-using-ed25519-keys-with-bouncy-castle-java
// https://www.agwa.name/blog/post/ssh_signatures
// https://blog.sigstore.dev/ssh-is-the-new-gpg-74b3c6cc51c0
// https://github.com/sigstore/rekor/blob/main/pkg/pki/ssh/README.md

// install rekor-cli
// make an entry and see if I can see the format of the entry being sent
// ask if there's anything special about the formatting

public class SshProcessor extends SigstoreProcessorSupport {

  @Override
  public SigstoreResult process(SigstoreRequest request) throws Exception {

    Path privateKey = request.sshRequest().privateKey();
    Path publicKey = request.sshRequest().publicKey();
    Builder resultBuilder = builder();
    Path artifact = request.artifact();
    Path sha256Path = artifact.resolveSibling(artifact.getFileName() + ".sha256");
    String sha256 = sha256(artifact);
    writeString(sha256Path, sha256);

    // Load private key
    AsymmetricKeyParameter privateKeyParameters = null;
    try (Reader fileReader = Files.newBufferedReader(privateKey);
        PemReader pemReader = new PemReader(fileReader)) {
      byte[] privateKeyContent = pemReader.readPemObject().getContent();
      privateKeyParameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(privateKeyContent);
    }

    // Load public key, Rekor just consumes the contents of the files and deals with it
    String publicKeyBody = Files.readString(publicKey);

    Path publicKeyPath = artifact.resolveSibling(artifact.getFileName() + ".sshpub");
    String publicKeyContent = base64(publicKeyBody.getBytes(StandardCharsets.UTF_8));
    writeString(publicKeyPath, publicKeyContent);
    resultBuilder.publicKeyContent(publicKeyContent);

    OpenSshSignature sshSignature = new OpenSshSignature(privateKey, publicKey);

    /*
    // ssh-keygen -Y sign -n file -f ${HOME}/.ssh/id_ed25519 ${file}
    String output = new ProcessExecutor().command(
            "ssh-keygen", "-Y", "sign", "-n", "file", "-f", "/Users/jvanzyl/.ssh/id_ed25519", artifact.toString())
        .readOutput(true).execute()
        .outputUTF8();
     */

    Path signaturePath = artifact.resolveSibling(artifact.getFileName() + ".sig");
    String signatureContent = Files.readString(signaturePath);
    resultBuilder.artifactSignatureContent(base64(signatureContent.getBytes(StandardCharsets.UTF_8)));
    SigstoreResult result = resultBuilder.build();
    Map<String, Object> rekord = rekord(request, result);
    return builder().from(result).rekorRecord(rekord).build();
  }
}
