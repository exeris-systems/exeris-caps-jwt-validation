package eu.exeris.caps.jwt.internal;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Fetches a JWKS document over HTTPS, or HTTP on a loopback host, with a bounded connect and response
 * time and a bounded body size.
 *
 * <p>Uses the JDK HTTP client, so the capability keeps no runtime dependency. A fetch that times out,
 * answers anything but 200, or exceeds the size bound throws; {@link JwksKeySet} then keeps the keys it
 * had. Redirects are not followed, so the configured URI is the only place keys come from.
 *
 * @since 0.1.0
 */
public final class HttpJwksFetcher implements Supplier<String> {

    private static final int MAX_BODY_BYTES = 64 * 1024;

    private final URI uri;
    private final Duration timeout;
    private final HttpClient client;

    public HttpJwksFetcher(URI uri, Duration timeout) {
        this.uri = Objects.requireNonNull(uri, "uri");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (!"https".equalsIgnoreCase(uri.getScheme()) && !isLoopback(uri)) {
            throw new IllegalArgumentException("A JWKS URI must be https unless it is a loopback address");
        }
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("JWKS fetch timeout must be positive");
        }
        this.client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public String get() {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Accept", "application/jwk-set+json, application/json")
                .GET()
                .build();
        try {
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                if (response.statusCode() != 200) {
                    throw new IllegalStateException("JWKS endpoint answered " + response.statusCode());
                }
                byte[] bytes = body.readNBytes(MAX_BODY_BYTES + 1);
                if (bytes.length > MAX_BODY_BYTES) {
                    throw new IllegalStateException("JWKS document exceeds " + MAX_BODY_BYTES + " bytes");
                }
                return new String(bytes, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("JWKS fetch failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("JWKS fetch interrupted", e);
        }
    }

    private static boolean isLoopback(URI uri) {
        String host = uri.getHost();
        return "http".equalsIgnoreCase(uri.getScheme())
                && host != null
                && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]") || host.equals("::1"));
    }
}
