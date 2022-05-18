package dev.sigstore.pgp.passphrase;

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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.SocketException;
import org.bouncycastle.util.encoders.Hex;
import org.newsclub.net.unix.AFUNIXSocket;
import org.newsclub.net.unix.AFUNIXSocketAddress;

public class GpgAgentPassphraseSource implements PassphraseSource {

  private static final File DEFAULT_AGENT_UNIX_SOCKET = new File(new File(System.getProperty("user.home")), ".gnupg/S.gpg-agent");

  public String load(long keyId) throws IOException {
    return load(keyId, DEFAULT_AGENT_UNIX_SOCKET);
  }

  public String load(long keyId, File socketFile) throws IOException {
    try (AFUNIXSocket sock = AFUNIXSocket.newInstance()) {
      try {
        sock.connect(AFUNIXSocketAddress.of(socketFile));
      } catch (SocketException e) {
        System.out.println("Cannot connect to server. Have you started it?");
        System.out.flush();
        throw e;
      }
      try (
          BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream())); //
          OutputStream os = sock.getOutputStream()) {

        expectOK(in);
        String display = System.getenv("DISPLAY");
        if (display != null) {
          os.write(("OPTION display=" + display + "\n").getBytes());
          os.flush();
          expectOK(in);
        }
        String term = System.getenv("TERM");
        if (term != null) {
          os.write(("OPTION ttytype=" + term + "\n").getBytes());
          os.flush();
          expectOK(in);
        }
        String hexKeyId = Long.toHexString(keyId & 0xFFFFFFFFL);
        // https://unix.stackexchange.com/questions/71135/how-can-i-find-out-what-keys-gpg-agent-has-cached-like-how-ssh-add-l-shows-yo
        String instruction = "GET_PASSPHRASE " + hexKeyId + " " + "Passphrase+incorrect" + " Passphrase Enter%20passphrase%20to%20unlock%20key+" + hexKeyId + "+for+signing+maven+artifact\n";
        os.write((instruction).getBytes());
        os.flush();
        return new String(Hex.decode(expectOK(in).trim()));
      }
    }
  }

  private String expectOK(BufferedReader in) throws IOException {
    String response = in.readLine();
    if (!response.startsWith("OK")) {
      throw new IOException("Expected OK but got this instead: " + response);
    }
    return response.substring(Math.min(response.length(), 3));
  }
}
