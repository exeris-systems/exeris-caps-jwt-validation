package eu.exeris.caps.jwt.internal;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("HttpJwksFetcher")
class HttpJwksFetcherTest {

    private HttpServer server;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/jwks", exchange -> {
            byte[] body = "{\"keys\":[]}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/slow", exchange -> {
            try {
                Thread.sleep(2_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.createContext("/missing", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
    }

    @Test
    void fetchesDocument() {
        assertThat(new HttpJwksFetcher(uri("/jwks"), Duration.ofSeconds(2)).get()).isEqualTo("{\"keys\":[]}");
    }

    @Test
    @DisplayName("gives up at the timeout")
    void timesOut() {
        HttpJwksFetcher fetcher = new HttpJwksFetcher(uri("/slow"), Duration.ofMillis(200));
        long start = System.nanoTime();
        assertThatThrownBy(fetcher::get).isInstanceOf(RuntimeException.class);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(1_500));
    }

    @Test
    void refusesNon200() {
        assertThatThrownBy(new HttpJwksFetcher(uri("/missing"), Duration.ofSeconds(2))::get)
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refusesPlainHttpOffLoopback() {
        assertThatThrownBy(() -> new HttpJwksFetcher(URI.create("http://issuer.example.test/jwks"), Duration.ofSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
