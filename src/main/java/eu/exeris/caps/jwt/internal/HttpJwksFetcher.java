package eu.exeris.caps.jwt.internal;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * Fetches a JWKS document over HTTPS, or HTTP on a loopback host, within one deadline that covers
 * connecting, the response headers and the whole body, and with a bounded body size.
 *
 * <p>Uses the JDK HTTP client, so the capability keeps no runtime dependency. A fetch that passes the deadline,
 * answers anything but 200, or exceeds the size bound is abandoned and throws; {@link JwksKeySet} then keeps the keys it
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
        AtomicBoolean oversized = new AtomicBoolean();
        CompletableFuture<HttpResponse<byte[]>> call = client.sendAsync(request, info -> bodyFor(info, oversized));
        try {
            HttpResponse<byte[]> response = call.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
            if (response.statusCode() != 200) {
                throw new IllegalStateException("JWKS endpoint answered " + response.statusCode());
            }
            return new String(response.body(), StandardCharsets.UTF_8);
        } catch (TimeoutException e) {
            throw new IllegalStateException("JWKS fetch exceeded " + timeout, e);
        } catch (ExecutionException e) {
            if (oversized.get()) {
                throw new IllegalStateException("JWKS document exceeds " + MAX_BODY_BYTES + " bytes", e.getCause());
            }
            throw new IllegalStateException("JWKS fetch failed", e.getCause());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("JWKS fetch interrupted", e);
        } finally {
            call.cancel(true);
        }
    }

    private static HttpResponse.BodySubscriber<byte[]> bodyFor(HttpResponse.ResponseInfo info, AtomicBoolean oversized) {
        return info.statusCode() == 200
                ? new BoundedBody(oversized)
                : HttpResponse.BodySubscribers.replacing(new byte[0]);
    }

    /** Collects a body and abandons the exchange as soon as it passes the size bound. */
    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {

        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream collected = new ByteArrayOutputStream();
        private final AtomicBoolean oversized;
        private Flow.Subscription subscription;

        BoundedBody(AtomicBoolean oversized) {
            this.oversized = oversized;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (collected.size() + buffer.remaining() > MAX_BODY_BYTES) {
                    oversized.set(true);
                    subscription.cancel();
                    result.completeExceptionally(
                            new IllegalStateException("JWKS document exceeds " + MAX_BODY_BYTES + " bytes"));
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                collected.write(chunk, 0, chunk.length);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(collected.toByteArray());
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }
    }

    private static boolean isLoopback(URI uri) {
        String host = uri.getHost();
        return "http".equalsIgnoreCase(uri.getScheme())
                && host != null
                && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]") || host.equals("::1"));
    }
}
