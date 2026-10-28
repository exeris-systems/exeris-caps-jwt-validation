package eu.exeris.caps.jwt.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwksKeySet")
class JwksKeySetTest {

    private static final long SECOND = 1_000_000_000L;
    private static final KeyPair ED_1 = TestTokens.ed25519();
    private static final KeyPair ED_2 = TestTokens.ed25519();

    @Test
    @DisplayName("binds each key to the algorithm its JWK implies and skips what it cannot bind")
    void parsesSupportedKeysOnly() {
        String jwks = TestTokens.jwks(
                TestTokens.okpJwk("ed", ED_1),
                TestTokens.rsaJwk("rsa", TestTokens.rsa(2048)),
                TestTokens.rsaJwk("rsa-small", TestTokens.rsa(1024)),
                TestTokens.okpJwk("mislabelled", ED_2).replace("\"alg\":\"EdDSA\"", "\"alg\":\"RS256\""),
                "{\"kty\":\"oct\",\"kid\":\"hmac\",\"k\":\"c2VjcmV0\"}",
                TestTokens.okpJwk("enc", ED_2).replace("\"use\":\"sig\"", "\"use\":\"enc\""));

        var keys = JwksKeySet.parse(jwks);

        assertThat(keys).containsOnlyKeys("ed", "rsa");
        assertThat(keys.get("ed").algorithm()).isEqualTo(JwksKeySet.EDDSA);
        assertThat(keys.get("rsa").algorithm()).isEqualTo(JwksKeySet.RS256);
    }

    @Test
    @DisplayName("a kid published twice is trusted in neither copy")
    void duplicateKidDropped() {
        var keys = JwksKeySet.parse(TestTokens.jwks(TestTokens.okpJwk("k", ED_1), TestTokens.okpJwk("k", ED_2)));
        assertThat(keys).isEmpty();
    }

    @Test
    @DisplayName("an unknown kid reloads the JWKS at most once per minimum refresh interval")
    void unknownKidRefreshIsRateLimited() {
        AtomicLong clock = new AtomicLong(100 * SECOND);
        AtomicInteger fetches = new AtomicInteger();
        AtomicReference<String> published = new AtomicReference<>(TestTokens.jwks(TestTokens.okpJwk("k1", ED_1)));
        Supplier<String> source = () -> {
            fetches.incrementAndGet();
            return published.get();
        };
        JwksKeySet keySet = JwksKeySet.fromSource(source, 300 * SECOND, 30 * SECOND, clock::get);

        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches).hasValue(1);

        for (int i = 0; i < 50; i++) {
            assertThat(keySet.find("invented-" + i)).isEmpty();
        }
        assertThat(fetches).hasValue(1);

        published.set(TestTokens.jwks(TestTokens.okpJwk("k1", ED_1), TestTokens.okpJwk("k2", ED_2)));
        clock.addAndGet(31 * SECOND);
        assertThat(keySet.find("k2")).isPresent();
        assertThat(fetches).hasValue(2);
    }

    @Test
    @DisplayName("a stale JWKS is reloaded, and a failed reload keeps the previous keys")
    void staleReloadAndFailure() {
        AtomicLong clock = new AtomicLong(0);
        AtomicInteger fetches = new AtomicInteger();
        AtomicReference<Boolean> failing = new AtomicReference<>(false);
        Supplier<String> source = () -> {
            fetches.incrementAndGet();
            if (failing.get()) {
                throw new IllegalStateException("endpoint down");
            }
            return TestTokens.jwks(TestTokens.okpJwk("k1", ED_1));
        };
        JwksKeySet keySet = JwksKeySet.fromSource(source, 300 * SECOND, 30 * SECOND, clock::get);
        assertThat(keySet.find("k1")).isPresent();

        clock.addAndGet(301 * SECOND);
        failing.set(true);
        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches).hasValue(2);

        clock.addAndGet(SECOND);
        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches).as("retries wait for the minimum interval").hasValue(2);
    }

    @Test
    @DisplayName("a key set whose last successful load is older than the maximum staleness answers empty until the endpoint recovers")
    void maxStalenessRefusesKeys() {
        AtomicLong clock = new AtomicLong(0);
        AtomicInteger fetches = new AtomicInteger();
        AtomicReference<Boolean> failing = new AtomicReference<>(false);
        Supplier<String> source = () -> {
            fetches.incrementAndGet();
            if (failing.get()) {
                throw new IllegalStateException("endpoint down");
            }
            return TestTokens.jwks(TestTokens.okpJwk("k1", ED_1));
        };
        // refreshInterval = 300s, minRefresh = 30s, maxStaleness = 600s
        JwksKeySet keySet = JwksKeySet.fromSource(source, 300 * SECOND, 30 * SECOND, 600 * SECOND, clock::get);
        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches).hasValue(1);

        // Fail subsequent reloads
        failing.set(true);

        // 350s: stale (> 300s) but within max staleness (600s), previous keys kept
        clock.set(350 * SECOND);
        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches).hasValue(2);

        // 599s: still within max staleness
        clock.set(599 * SECOND);
        assertThat(keySet.find("k1")).isPresent();

        // 600s: reaches max staleness limit -> answers empty
        clock.set(600 * SECOND);
        assertThat(keySet.find("k1")).isEmpty();

        // 700s: still past limit -> answers empty
        clock.set(700 * SECOND);
        assertThat(keySet.find("k1")).isEmpty();

        // Endpoint recovers at 800s -> fresh load restores keys
        clock.set(800 * SECOND);
        failing.set(false);
        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches.get()).isGreaterThan(2);
    }

    @Test
    @DisplayName("fromSource requires maximum staleness greater than refresh interval")
    void fromSourceValidatesMaxStaleness() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                JwksKeySet.fromSource(() -> "{}", 300 * SECOND, 30 * SECOND, 300 * SECOND, () -> 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximum staleness must be > the refresh interval");

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                JwksKeySet.fromSource(() -> "{}", 300 * SECOND, 30 * SECOND, 200 * SECOND, () -> 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximum staleness must be > the refresh interval");
    }

    @Test
    @DisplayName("on first use, concurrent waiters on the refresh lock time out after the fetch deadline and fail closed")
    void firstUseLockTimeoutFailsClosed() throws Exception {
        CountDownLatch fetchStarted = new CountDownLatch(1);
        CountDownLatch finishFetch = new CountDownLatch(1);
        AtomicInteger fetches = new AtomicInteger();
        Supplier<String> source = () -> {
            fetches.incrementAndGet();
            fetchStarted.countDown();
            try {
                finishFetch.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return TestTokens.jwks(TestTokens.okpJwk("k1", ED_1));
        };
        // fetchTimeout = 50ms
        JwksKeySet keySet = JwksKeySet.fromSource(source, 300 * SECOND, 30 * SECOND,
                86400 * SECOND, 50 * 1_000_000L, System::nanoTime);

        Thread holder = new Thread(() -> keySet.find("k1"));
        holder.start();
        assertThat(fetchStarted.await(5, TimeUnit.SECONDS)).isTrue();

        // Calling find on another thread while fetch is in progress times out after 50ms and fails closed
        assertThat(keySet.find("k1")).isEmpty();

        finishFetch.countDown();
        holder.join();

        // Now that the lock is released, find succeeds with the loaded key
        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches).hasValue(1);
    }

    @Test
    @DisplayName("on a stale document, concurrent waiters on the refresh lock time out after the fetch deadline and fail closed")
    void staleDocumentLockTimeoutFailsClosed() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch finishRefresh = new CountDownLatch(1);
        AtomicBoolean blocking = new AtomicBoolean(false);
        AtomicInteger fetches = new AtomicInteger();
        Supplier<String> source = () -> {
            fetches.incrementAndGet();
            if (blocking.get()) {
                refreshStarted.countDown();
                try {
                    finishRefresh.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return TestTokens.jwks(TestTokens.okpJwk("k1", ED_1));
        };
        // fetchTimeout = 50ms
        JwksKeySet keySet = JwksKeySet.fromSource(source, 300 * SECOND, 30 * SECOND,
                86400 * SECOND, 50 * 1_000_000L, clock::get);

        // Initial load succeeds
        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches).hasValue(1);

        // Document becomes stale (> 300s)
        clock.set(301 * SECOND);
        blocking.set(true);

        Thread holder = new Thread(() -> keySet.find("k1"));
        holder.start();
        assertThat(refreshStarted.await(5, TimeUnit.SECONDS)).isTrue();

        // Concurrent caller on stale document times out waiting on the lock and fails closed
        assertThat(keySet.find("k1")).isEmpty();

        finishRefresh.countDown();
        holder.join();

        // After refresh finishes, key is accessible
        assertThat(keySet.find("k1")).isPresent();
    }

    @Test
    @DisplayName("on an unknown kid, concurrent waiters on the refresh lock time out after the fetch deadline and fail closed")
    void unknownKidLockTimeoutFailsClosed() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        CountDownLatch refreshStarted = new CountDownLatch(1);
        CountDownLatch finishRefresh = new CountDownLatch(1);
        AtomicBoolean blocking = new AtomicBoolean(false);
        AtomicInteger fetches = new AtomicInteger();
        Supplier<String> source = () -> {
            fetches.incrementAndGet();
            if (blocking.get()) {
                refreshStarted.countDown();
                try {
                    finishRefresh.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return TestTokens.jwks(TestTokens.okpJwk("k1", ED_1), TestTokens.okpJwk("k2", ED_2));
            }
            return TestTokens.jwks(TestTokens.okpJwk("k1", ED_1));
        };
        // fetchTimeout = 50ms
        JwksKeySet keySet = JwksKeySet.fromSource(source, 300 * SECOND, 30 * SECOND,
                86400 * SECOND, 50 * 1_000_000L, clock::get);

        assertThat(keySet.find("k1")).isPresent();
        assertThat(fetches).hasValue(1);

        // Unknown kid triggers refresh
        clock.set(31 * SECOND);
        blocking.set(true);

        Thread holder = new Thread(() -> keySet.find("k2"));
        holder.start();
        assertThat(refreshStarted.await(5, TimeUnit.SECONDS)).isTrue();

        // Concurrent caller for unknown kid times out waiting on the lock and fails closed
        assertThat(keySet.find("k2")).isEmpty();

        finishRefresh.countDown();
        holder.join();

        // After refresh finishes, k2 is present
        assertThat(keySet.find("k2")).isPresent();
    }

    @Test
    @DisplayName("fromSource requires positive fetch timeout")
    void fromSourceValidatesFetchTimeout() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                JwksKeySet.fromSource(() -> "{}", 300 * SECOND, 30 * SECOND, 600 * SECOND, 0, () -> 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fetch timeout must be > 0");

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                JwksKeySet.fromSource(() -> "{}", 300 * SECOND, 30 * SECOND, 600 * SECOND, -1, () -> 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fetch timeout must be > 0");
    }
}
