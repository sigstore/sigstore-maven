package dev.sigstore.pgp;

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

import static org.bouncycastle.openpgp.PGPUtil.getDecoderStream;

import dev.sigstore.pgp.passphrase.PgpPassphraseFinder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PgpSigner {

  private static final Logger logger = LoggerFactory.getLogger(PgpSigner.class);

  private final PGPSecretKey secretKey;
  private final PgpKeyLocator locator;
  private final PgpPassphraseFinder passphraseFinder;
  private final PgpSigningRequest request;
  private final Path gpgHomedir;

  public PgpSigner(PgpSigningRequest request) {
    try {
      Security.addProvider(new BouncyCastleProvider());
      this.request = request;
      this.locator = new PgpKeyLocator(request);
      this.gpgHomedir = locator.gpgHomedir();
      if(request.privateKeyFromPath() != null) {
        this.secretKey = loadKeyFromArmoredPath(request.privateKeyFromPath());
      } else {
        this.secretKey = locator.findPgpSecretKey();
      }
      this.passphraseFinder = new PgpPassphraseFinder();
    } catch(Exception e) {
      throw new RuntimeException(e);
    }
  }

  public File sign(File fileToSign) throws IOException, PGPException {
    return sign(fileToSign, request.privateKeyPassphrase());
  }

  private File sign(File fileToSign, String passphrase) throws IOException, PGPException {
    if (passphrase == null) {
      passphrase = findPassphrase();
    }
    File signatureFile = new File(fileToSign.getParentFile(), fileToSign.getName() + ".asc");
    try (InputStream inputStream = new FileInputStream(fileToSign); OutputStream outputStream = new FileOutputStream(signatureFile)) {
      signMessage(passphrase, inputStream, outputStream);
    }
    return signatureFile;
  }

  private String findPassphrase() {
    return passphraseFinder.find(gpgHomedir, secretKey.getKeyID());
  }

  private static PGPSecretKey loadKeyFromArmoredPath(Path keyFile) throws IOException {
    try (InputStream inputStream = Files.newInputStream(keyFile)) {
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());
      Object pgpObject = pgpObjectFactory.nextObject();
      if (!(pgpObject instanceof PGPSecretKeyRing)) {
        throw new IOException(keyFile + " doesn't contain PGP private key!");
      }
      PGPSecretKeyRing keyRing = (PGPSecretKeyRing) pgpObject;
      return keyRing.getSecretKey();
    }
  }

  public boolean signMessage(String passwordOfPrivateKey, InputStream message, OutputStream signature) throws PGPException, IOException {
    PGPPrivateKey privateKey = findPrivateKey(secretKey, passwordOfPrivateKey);
    return signatureGenerator(message, signature, privateKey);
  }

  private boolean signatureGenerator(InputStream message, OutputStream signature, PGPPrivateKey privateKey) throws PGPException, IOException {
    final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA256));
    signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
    try (BCPGOutputStream outputStream = new BCPGOutputStream(new ArmoredOutputStream(signature))) {
      process(message, signatureGenerator::update);
      signatureGenerator.generate().encode(outputStream);
    }
    return true;
  }

  public boolean verify(Path armoredPublicKey, Path artifact, Path signature) {
    try {
      return verifyMessage(
          Files.newInputStream(armoredPublicKey),
          Files.newInputStream(artifact),
          Files.newInputStream(signature));
    } catch (IOException e) {
      return false;
    }
  }

  public boolean verifyMessage(InputStream publicKeyOfSender, InputStream message, InputStream signatureStream) {
    boolean result = false;
    try (InputStream armordPublicKeyStream = new ArmoredInputStream(signatureStream)) {
      Object pgpObject;
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(armordPublicKeyStream, new BcKeyFingerprintCalculator());
      while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
        if (pgpObject instanceof PGPSignatureList) {
          PGPSignatureList signatureList = (PGPSignatureList) pgpObject;
          for (PGPSignature signature : signatureList) {
            PGPPublicKey pgpPublicKey = findPublicKey(publicKeyOfSender, pgpKey -> pgpKey.getKeyID() == signature.getKeyID());
            if (pgpPublicKey != null) {
              signature.init(new BcPGPContentVerifierBuilderProvider(), pgpPublicKey);
              process(message, signature::update);
              result = signature.verify();
            }
          }
        }
      }
    } catch (IOException | PGPException e) {
      result = false;
    }
    return result;
  }

  private PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecretKey, String password) throws PGPException {
    PBESecretKeyDecryptor pbeSecretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder(
        new JcaPGPDigestCalculatorProviderBuilder().build()).build(password.toCharArray());
    return pgpSecretKey.extractPrivateKey(pbeSecretKeyDecryptor);
  }

  private PGPPublicKey findPublicKey(InputStream publicKey, KeyFilter<PGPPublicKey> keyFilter) {
    return retrievePublicKey(readPublicKeyRing(publicKey), keyFilter);
  }

  private PGPPublicKey retrievePublicKey(PGPPublicKeyRing publicKeyRing, KeyFilter<PGPPublicKey> keyFilter) {
    PGPPublicKey result = null;
    Iterator<PGPPublicKey> publicKeyIterator = publicKeyRing.getPublicKeys();
    while (result == null && publicKeyIterator.hasNext()) {
      PGPPublicKey key = publicKeyIterator.next();
      if (keyFilter.accept(key)) {
        result = key;
      }
    }
    return result;
  }

  private PGPPublicKeyRing readPublicKeyRing(InputStream publicKey) {
    PGPPublicKeyRing result = null;
    try (InputStream decoderStream = PGPUtil.getDecoderStream(publicKey)) {
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
      Object o;
      while ((o = pgpObjectFactory.nextObject()) != null && result == null) {
        if (o instanceof PGPPublicKeyRing) {
          result = (PGPPublicKeyRing) o;
        }
      }
    } catch (IOException ignored) {
    }
    return result;
  }

  public interface KeyFilter<T> {

    boolean accept(T pgpKey);

  }

  public static void process(InputStream inputStream, StreamHandler handler) throws IOException {
    process(inputStream, handler, new byte[4096]);
  }

  public static void process(InputStream inputStream, StreamHandler handler, byte[] buffer) throws IOException {
    int read;
    while ((read = inputStream.read(buffer)) != -1) {
      handler.handleStreamBuffer(buffer, 0, read);
    }
  }

  public interface StreamHandler {

    void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException;

  }
}
