package dev.sigstore.pgp;

import java.nio.file.Path;
import javax.annotation.Nullable;
import org.immutables.value.Value;

@Value.Immutable
public abstract class PgpSigningRequest {

  public static final String FIRST = "@first";

  @Value.Default
  public String signingKeyId() {
    return FIRST;
  }

  @Nullable
  public abstract Path gpgHomedir();

  @Value.Default
  public boolean privateKeyFromEnvar() {
    return false;
  }

  @Nullable
  public abstract Path privateKeyFromPath();

  @Nullable
  public abstract String privateKeyPassphrase();

}
