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

import static java.nio.file.Paths.get;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class CliCommand {

  private final Path workDir;
  private final List<String> args;
  private final Map<String, String> envars;
  private final boolean saveOutput;
  private final boolean quiet;

  public CliCommand(String args, boolean saveOutput) {
    this(Arrays.asList(args.split(" ")), get(System.getProperty("user.dir")), new HashMap<>(), saveOutput);
  }

  public CliCommand(String args, Path workDir, Map<String, String> envars, boolean saveOutput) {
    this(Arrays.asList(args.split(" ")), workDir, envars, saveOutput);
  }

  public CliCommand(List<String> args, Path workDir, Map<String, String> envars, boolean saveOutput) {
    this.workDir = workDir;
    this.args = args;
    this.envars = envars;
    this.saveOutput = saveOutput;
    this.quiet = true;
  }

  protected static void log(String line) {
    System.out.println(line);
  }

  public Result execute()
      throws Exception {
    return execute(Executors.newCachedThreadPool());
  }

  public Result execute(ExecutorService executor)
      throws Exception {
    ProcessBuilder pb = new ProcessBuilder(args).directory(workDir.toFile());
    Map<String, String> combinedEnv = new HashMap<>(envars);
    pb.environment().putAll(combinedEnv);
    Process p = pb.start();
    Future<String> stderr = executor.submit(new StreamReader(saveOutput, quiet, p.getErrorStream()));
    Future<String> stdout = executor.submit(new StreamReader(saveOutput, quiet, p.getInputStream()));
    int code = p.waitFor();
    executor.shutdown();
    return new Result(code, stdout.get(), stderr.get());
  }

  private static class StreamReader
      implements Callable<String> {

    private final boolean saveOutput;
    private final boolean quiet;
    private final InputStream in;

    private StreamReader(boolean saveOutput, boolean quiet, InputStream in) {
      this.saveOutput = saveOutput;
      this.quiet = quiet;
      this.in = in;
    }

    @Override
    public String call() throws Exception {
      StringBuilder sb = new StringBuilder();
      try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
        String line;
        while ((line = reader.readLine()) != null) {
          if (saveOutput) {
            sb.append(line).append(System.lineSeparator());
          }
          if(!quiet) {
            log(line);
          }
        }
      }
      return sb.toString();
    }
  }

  public static class Result {

    private final int code;
    private final String stdout;
    private final String stderr;

    public Result(int code, String stdout, String stderr) {
      this.code = code;
      this.stdout = stdout;
      this.stderr = stderr;
    }

    public int getCode() {
      return code;
    }

    public String getStdout() {
      return stdout;
    }

    public String getStderr() {
      return stderr;
    }
  }
}