package eu.exeris.caps.jwt.internal;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The verification keys of one issuer, by {@code kid}, each bound to the one JWS algorithm it verifies.
 *
 * <p>A key's algorithm comes from the JWK itself ({@code kty}, {@code crv}, and {@code alg} when present),
 * never from the token: an Ed25519 key verifies only {@code EdDSA}, an RSA key only {@code RS256}.
 *
 * <p>A key set backed by a JWKS source reloads the document when it is older than the refresh interval,
 * and on a {@code kid} it does not know, at most once per minimum refresh interval, so a stream of tokens
 * with invented {@code kid}s cannot turn into a stream of fetches. A failed reload keeps the keys it had.
 *
 * @since 0.1.0
 */
public final class JwksKeySet {

    /** Algorithm a key verifies. */
    public static final String EDDSA = "EdDSA";
    /** Algorithm a key verifies. */
    public static final String RS256 = "RS256";

    private static final int MIN_RSA_BITS = 2048;
    private static final byte[] ED25519_X509_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    /**
     * A verification key and the single algorithm it is allowed to verify.
     *
     * @param kid key id
     * @param algorithm JWS algorithm bound to the key
     * @param publicKey the key
     */
    public record JwkKey(String kid, String algorithm, PublicKey publicKey) {
        public JwkKey {
            Objects.requireNonNull(kid, "kid");
            Objects.requireNonNull(algorithm, "algorithm");
            Objects.requireNonNull(publicKey, "publicKey");
        }
    }

    private final Supplier<String> source;
    private final long refreshIntervalNanos;
    private final long minRefreshIntervalNanos;
    private final LongSupplier nanoClock;
    private final ReentrantLock refreshLock = new ReentrantLock();

    private volatile Map<String, JwkKey> keys;
    private volatile boolean loaded;
    private volatile long lastAttemptNanos;
    private volatile long lastSuccessNanos;

    private JwksKeySet(Supplier<String> source, Map<String, JwkKey> keys, long refreshIntervalNanos,
                       long minRefreshIntervalNanos, LongSupplier nanoClock) {
        this.source = source;
        this.keys = keys;
        this.loaded = source == null;
        this.refreshIntervalNanos = refreshIntervalNanos;
        this.minRefreshIntervalNanos = minRefreshIntervalNanos;
        this.nanoClock = nanoClock;
    }

    /**
     * A key set loaded from a JWKS source on first use and refreshed as described above.
     *
     * @param source returns the current JWKS document; may throw on fetch failure
     * @param refreshIntervalNanos age after which the document is reloaded
     * @param minRefreshIntervalNanos minimum spacing of reloads, including those an unknown {@code kid} triggers
     * @param nanoClock monotonic clock
     * @return the key set
     */
    public static JwksKeySet fromSource(Supplier<String> source, long refreshIntervalNanos,
                                        long minRefreshIntervalNanos, LongSupplier nanoClock) {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(nanoClock, "nanoClock");
        if (minRefreshIntervalNanos <= 0 || refreshIntervalNanos < minRefreshIntervalNanos) {
            throw new IllegalArgumentException("refresh interval must be >= the minimum refresh interval > 0");
        }
        return new JwksKeySet(source, Map.of(), refreshIntervalNanos, minRefreshIntervalNanos, nanoClock);
    }

    /**
     * A fixed key set that never reloads.
     *
     * @param keys the keys
     * @return the key set
     */
    public static JwksKeySet fixed(List<JwkKey> keys) {
        Map<String, JwkKey> byKid = new HashMap<>();
        for (JwkKey key : keys) {
            if (byKid.putIfAbsent(key.kid(), key) != null) {
                throw new IllegalArgumentException("Duplicate kid in key set");
            }
            requireUsable(key);
        }
        return new JwksKeySet(null, Map.copyOf(byKid), Long.MAX_VALUE, Long.MAX_VALUE, System::nanoTime);
    }

    /**
     * Binds a public key to the algorithm its type implies.
     *
     * @param kid key id
     * @param publicKey Ed25519 or RSA public key
     * @return the bound key
     */
    public static JwkKey bind(String kid, PublicKey publicKey) {
        if (publicKey instanceof EdECPublicKey ed && "Ed25519".equalsIgnoreCase(ed.getParams().getName())) {
            return new JwkKey(kid, EDDSA, publicKey);
        }
        if (publicKey instanceof RSAPublicKey) {
            return new JwkKey(kid, RS256, publicKey);
        }
        throw new IllegalArgumentException("Only Ed25519 and RSA verification keys are supported");
    }

    /**
     * Finds the key for {@code kid}, reloading the source first when it is stale and once more when the
     * {@code kid} is unknown and the minimum refresh interval has passed.
     *
     * @param kid key id from the token header
     * @return the key, or empty when the issuer publishes no such key
     */
    public Optional<JwkKey> find(String kid) {
        if (source != null) {
            long now = nanoClock.getAsLong();
            if (!loaded || now - lastSuccessNanos >= refreshIntervalNanos) {
                refresh(now);
            }
        }
        JwkKey key = keys.get(kid);
        if (key == null && source != null) {
            refresh(nanoClock.getAsLong());
            key = keys.get(kid);
        }
        return Optional.ofNullable(key);
    }

    private void refresh(long now) {
        if (loaded && now - lastAttemptNanos < minRefreshIntervalNanos) {
            return;
        }
        refreshLock.lock();
        try {
            if (loaded && now - lastAttemptNanos < minRefreshIntervalNanos) {
                return;
            }
            lastAttemptNanos = now;
            try {
                keys = parse(source.get());
                lastSuccessNanos = now;
            } catch (RuntimeException fetchOrParseFailure) {
                // The previous keys stay in force; the next attempt waits for the minimum interval.
            }
            loaded = true;
        } finally {
            refreshLock.unlock();
        }
    }

    /**
     * Parses a JWKS document into the keys this verifier can use, skipping any key it cannot bind to
     * exactly one supported algorithm.
     *
     * @param jwksJson JWKS document
     * @return keys by {@code kid}
     * @throws IllegalArgumentException if the document is not a JWKS
     */
    public static Map<String, JwkKey> parse(String jwksJson) {
        Map<String, Object> doc = Json.parseObject(Objects.requireNonNull(jwksJson, "jwksJson"));
        if (!(doc.get("keys") instanceof List<?> list)) {
            throw new IllegalArgumentException("JWKS document has no keys array");
        }
        Map<String, JwkKey> byKid = new HashMap<>();
        java.util.Set<String> duplicated = new java.util.HashSet<>();
        for (Object entry : list) {
            if (!(entry instanceof Map<?, ?> jwk)) {
                continue;
            }
            JwkKey key = toKey(jwk);
            if (key == null) {
                continue;
            }
            if (byKid.putIfAbsent(key.kid(), key) != null) {
                duplicated.add(key.kid());
            }
        }
        // A kid published twice is ambiguous, so neither copy is trusted.
        duplicated.forEach(byKid::remove);
        return Map.copyOf(byKid);
    }

    private static JwkKey toKey(Map<?, ?> jwk) {
        String kid = string(jwk, "kid");
        String kty = string(jwk, "kty");
        String use = string(jwk, "use");
        String alg = string(jwk, "alg");
        if (kid == null || kid.isEmpty() || kty == null || (use != null && !"sig".equals(use))) {
            return null;
        }
        try {
            JwkKey key;
            if ("OKP".equals(kty) && "Ed25519".equals(string(jwk, "crv"))) {
                key = new JwkKey(kid, EDDSA, ed25519(string(jwk, "x")));
            } else if ("RSA".equals(kty)) {
                key = new JwkKey(kid, RS256, rsa(string(jwk, "n"), string(jwk, "e")));
            } else {
                return null;
            }
            if (alg != null && !alg.equals(key.algorithm())) {
                return null;
            }
            requireUsable(key);
            return key;
        } catch (RuntimeException | java.security.GeneralSecurityException invalidKey) {
            return null;
        }
    }

    private static void requireUsable(JwkKey key) {
        if (key.publicKey() instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new IllegalArgumentException("RSA verification keys must be at least " + MIN_RSA_BITS + " bits");
        }
    }

    private static PublicKey ed25519(String x) throws java.security.GeneralSecurityException {
        byte[] raw = Base64.getUrlDecoder().decode(Objects.requireNonNull(x, "x"));
        if (raw.length != 32) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        byte[] encoded = new byte[ED25519_X509_PREFIX.length + raw.length];
        System.arraycopy(ED25519_X509_PREFIX, 0, encoded, 0, ED25519_X509_PREFIX.length);
        System.arraycopy(raw, 0, encoded, ED25519_X509_PREFIX.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static PublicKey rsa(String n, String e) throws java.security.GeneralSecurityException {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        BigInteger modulus = new BigInteger(1, decoder.decode(Objects.requireNonNull(n, "n")));
        BigInteger exponent = new BigInteger(1, decoder.decode(Objects.requireNonNull(e, "e")));
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    private static String string(Map<?, ?> map, String name) {
        return map.get(name) instanceof String s ? s : null;
    }
}
