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

import static java.nio.file.Files.createDirectories;
import static java.nio.file.Files.exists;
import static java.nio.file.Paths.get;

import ca.vanzyl.provisio.archive.generator.JarArtifactGenerator;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

public class SigstoreTestSupport {

  protected String basedir() {
    return new File("").getAbsolutePath();
  }

  protected Path artifacts() {
    return get(basedir()).resolve("target").resolve("artifacts");
  }

  protected ImmutableSigstoreRequest.Builder localRequestBuilder() {
    return ImmutableSigstoreRequest.builder()
        .rekorInstanceURL("http://rekor.rekor-system.svc:8080")
        .fulcioInstanceURL("http://fulcio.fulcio-system.svc:8080");
  }

  protected Path jarArtifact(String name) throws IOException {
    Path jar = artifacts().resolve(name + ".jar");
    if(!exists(jar.getParent())) {
      createDirectories(jar.getParent());
    }
    JarArtifactGenerator generator = new JarArtifactGenerator(jar.toFile(), 1);
    generator.generate();
    return jar;
  }
}
