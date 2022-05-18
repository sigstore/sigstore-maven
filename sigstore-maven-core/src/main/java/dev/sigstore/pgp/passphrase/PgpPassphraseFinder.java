package dev.sigstore.pgp.passphrase;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PgpPassphraseFinder {

  private static final Logger logger = LoggerFactory.getLogger(PgpPassphraseFinder.class);
  public static final String SIGSTORE_GPG_PASSPHRASE_FILE = ".pgp.passphrase";

  public String find(Path gpgHomedir, long keyId) {
    try {
      String passphrase = System.getenv("PGP_PASSPHRASE");
      if (passphrase != null) {
        logger.debug("Found passphrase in envar PGP_PASSPHRASE.");
        return passphrase;
      }

      Path gpgPassphraseFile = gpgHomedir.resolve(SIGSTORE_GPG_PASSPHRASE_FILE);
      passphrase = new FilePassphraseSource(gpgPassphraseFile).load(keyId);
      if (passphrase != null) {
        logger.debug("Found passphrase " + gpgPassphraseFile);
        return passphrase;
      }

      passphrase = new GpgAgentPassphraseSource().load(keyId);
      if (passphrase != null) {
        logger.debug("Found passphrase from gpg agent.");
        return passphrase;
      }

      return passphrase;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public char[] getPassphrase(Path gpgHomedir, long keyId) {
    return new String(find(gpgHomedir, keyId).getBytes(StandardCharsets.UTF_8)).toCharArray();
  }
}
