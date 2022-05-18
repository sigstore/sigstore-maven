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

import static java.nio.file.Files.exists;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class FilePassphraseSource implements PassphraseSource {

  private Path file;

  public FilePassphraseSource(Path file) {
    this.file = file;
  }

  public String load(long keyId) throws IOException {
    if (!exists(file)) {
      return null;
    }
    return new String(Files.readAllBytes(file)).trim();
  }
}
