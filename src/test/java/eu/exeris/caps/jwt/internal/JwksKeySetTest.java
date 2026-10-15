package eu.exeris.caps.jwt.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
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
}
