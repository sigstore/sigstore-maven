package dev.sigstore.pgp;

import java.nio.file.Path;
import org.bouncycastle.openpgp.PGPSecretKey;

public class PgpKey {

  private PGPSecretKey secretKey;

  private Path origin;

  public PgpKey(PGPSecretKey secretKey, Path origin) {
    this.secretKey = secretKey;
    this.origin = origin;
  }

  public PGPSecretKey getSecretKey() {
    return secretKey;
  }

  public Path getOrigin() {
    return origin;
  }
}
