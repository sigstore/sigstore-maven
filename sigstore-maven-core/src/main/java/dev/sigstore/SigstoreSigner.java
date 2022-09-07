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

import static dev.sigstore.ImmutableSigstoreResult.builder;
import static dev.sigstore.SigstoreRequest.Type.X_509;
import static java.lang.String.format;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import dev.sigstore.ImmutableSigstoreResult.Builder;
import dev.sigstore.x509.FulcioProcessor;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SigstoreSigner {

  public static final int HTTP_201 = 201;
  private static final Logger LOGGER = LoggerFactory.getLogger(SigstoreSigner.class);

  private SigstoreRequest request;
  private SigstoreResult result;

  public SigstoreSigner(SigstoreRequest request) {
    this.request = request;
  }

  public static Builder newResultFrom(SigstoreResult result) {
    return builder().from(result);
  }

  public static String base64(Path path) throws IOException {
    return Base64.getEncoder().encodeToString(Files.readAllBytes(path));
  }

  // -----------------------------------------------------------------------------------------------------------------
  //
  // -----------------------------------------------------------------------------------------------------------------

  public static String base64(byte[] input) {
    return Base64.getEncoder().encodeToString(input);
  }

  public static String base64Mime(byte[] input, int length) {
    final String lineSeparator = System.getProperty("line.separator");
    Base64.Encoder encoder = Base64.getMimeEncoder(length, lineSeparator.getBytes());
    return new String(encoder.encode(input));
  }

  public static String sha256(Path path) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(Files.readAllBytes(path));
    StringBuilder hexString = new StringBuilder(2 * hash.length);
    for (int i = 0; i < hash.length; i++) {
      String hex = Integer.toHexString(0xff & hash[i]);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    return hexString.toString();
  }

  public static byte[] sha512(byte[] input) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    return digest.digest(input);
  }

  public static HttpTransport getHttpTransport(SigstoreRequest request) {
    HttpClientBuilder hcb = ApacheHttpTransport.newDefaultHttpClientBuilder();
    if (!request.sslVerfication()) {
      hcb = hcb.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
    }
    return new ApacheHttpTransport(hcb.build());
  }

  public SigstoreResult sign() throws Exception {
    SigstoreProcessor processor = new FulcioProcessor();
    if (request.type().equals(X_509)) {
      processor = new FulcioProcessor();
    } 
    SigstoreResult result = processor.process(request);
    result = submitRecordToRekor(request, result);
    LOGGER.info(format("Created entry in transparency log for %s @ '%s'", request.artifact().getFileName().toString(), result.rekorEntryUrl()));
    return result;
  }

  public SigstoreResult submitRecordToRekor(SigstoreRequest request, SigstoreResult result) throws Exception {
    //TODO: Stream the contents and don't place the artifact in memory
    try {
      HttpTransport httpTransport = getHttpTransport(request);
      ObjectMapper m = new ObjectMapper();
      String json = m.writerWithDefaultPrettyPrinter().writeValueAsString(result.rekorRecord());
      byte[] rekorContent = json.getBytes(StandardCharsets.UTF_8);
      HttpContent rekorJsonContent = new ByteArrayContent(null, rekorContent);
      ByteArrayOutputStream rekorStream = new ByteArrayOutputStream();
      rekorJsonContent.writeTo(rekorStream);
      GenericUrl rekorPostUrl = new GenericUrl(request.rekorInstanceURL() + "/api/v1/log/entries");
      HttpRequest rekorReq = httpTransport.createRequestFactory().buildPostRequest(rekorPostUrl, rekorJsonContent);
      rekorReq.getHeaders().set("Accept", "application/json");
      rekorReq.getHeaders().set("Content-Type", "application/json");
      HttpResponse rekorResp = rekorReq.execute();
      if (rekorResp.getStatusCode() != HTTP_201) {
        throw new IOException("bad response from rekor: " + rekorResp.parseAsString());
      }
      URL rekorEntryUrl = new URL(new URL(request.rekorInstanceURL()), rekorResp.getHeaders().getLocation());
      return builder().from(result).rekorEntryUrl(rekorEntryUrl.toExternalForm()).build();
    } catch (Exception e) {
      throw new Exception(format("Error in submitting entry to Rekor @ %s:", request.rekorInstanceURL()), e);
    }
  }
}
