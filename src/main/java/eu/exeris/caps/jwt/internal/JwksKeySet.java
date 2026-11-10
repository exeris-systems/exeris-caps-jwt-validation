package eu.exeris.caps.jwt.internal;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * The verification keys of one issuer, by {@code kid}, each bound to the one JWS algorithm it verifies.
 *
 * <p>A key's algorithm comes from the JWK itself ({@code kty}, {@code crv}, and {@code alg} when present),
 * never from the token: an Ed25519 key verifies only {@code EdDSA}, an RSA key only {@code RS256}.
 *
 * <p>A key set backed by a JWKS source is refreshed by one background virtual thread, the only caller of
 * the source. {@link #find(String)} reads an immutable snapshot through one volatile field: it takes no
 * lock, performs no I/O and never waits for a reload. The refresher reloads the document when it is older
 * than the refresh interval, and early when a lookup met a {@code kid} it does not know, never sooner than
 * the minimum refresh interval after its previous attempt, so a stream of tokens with invented
 * {@code kid}s cannot turn into a stream of fetches. A failed reload keeps the keys held until the last
 * successful load is older than the maximum staleness, after which every key is refused; so is every key
 * before the first successful load.
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
    private static final long DAY_NANOS = 86_400L * 1_000_000_000L;
    private static final long WEEK_NANOS = 7 * DAY_NANOS;
    private static final String REFRESHER_NAME = "exeris-jwt-jwks-refresh";
    private static final System.Logger LOG = System.getLogger(JwksKeySet.class.getName());

    /** The keys of one load and the instant it completed. */
    private record Snapshot(Map<String, JwkKey> keys, long loadedAtNanos) {
    }

    /** Marks a source-backed key set that has not loaded yet; compared by identity. */
    private static final Snapshot NOT_LOADED = new Snapshot(Map.of(), 0L);

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
    private final long maxStalenessNanos;
    private final LongSupplier nanoClock;

    /** The only state {@link #find(String)} reads. */
    private volatile Snapshot snapshot;
    private final AtomicBoolean refreshRequested = new AtomicBoolean();
    private final CountDownLatch firstAttempt = new CountDownLatch(1);
    /** Guards start and stop only, never the request path. */
    private final Object lifecycle = new Object();
    /** Written once under {@link #lifecycle}, before the thread starts; read without it on the request path. */
    private volatile Thread refresher;
    private volatile boolean stopped;
    private long awaitNanos;
    // Confined to the refresher thread.
    private boolean attempted;
    private boolean lastAttemptFailed;
    private long lastAttemptNanos;

    private JwksKeySet(Supplier<String> source, Snapshot snapshot, long refreshIntervalNanos,
                       long minRefreshIntervalNanos, long maxStalenessNanos, LongSupplier nanoClock) {
        this.source = source;
        this.snapshot = snapshot;
        this.refreshIntervalNanos = refreshIntervalNanos;
        this.minRefreshIntervalNanos = minRefreshIntervalNanos;
        this.maxStalenessNanos = maxStalenessNanos;
        this.nanoClock = nanoClock;
    }

    /**
     * A key set refreshed in the background from {@code source}; nothing is fetched until {@link #start}.
     * {@code maxStalenessNanos} must exceed the refresh interval.
     *
     * @param source returns the current JWKS document; may throw on fetch failure
     * @param refreshIntervalNanos age after which the document is reloaded
     * @param minRefreshIntervalNanos minimum spacing of reloads, including those an unknown {@code kid} requests
     * @param maxStalenessNanos maximum age of keys since the last successful load before they are refused
     * @param nanoClock monotonic clock
     * @return the key set
     */
    public static JwksKeySet fromSource(Supplier<String> source, long refreshIntervalNanos,
                                        long minRefreshIntervalNanos, long maxStalenessNanos,
                                        LongSupplier nanoClock) {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(nanoClock, "nanoClock");
        if (minRefreshIntervalNanos <= 0 || refreshIntervalNanos < minRefreshIntervalNanos) {
            throw new IllegalArgumentException("refresh interval must be >= the minimum refresh interval > 0");
        }
        if (maxStalenessNanos <= refreshIntervalNanos) {
            throw new IllegalArgumentException("maximum staleness must be > the refresh interval");
        }
        return new JwksKeySet(source, NOT_LOADED, refreshIntervalNanos, minRefreshIntervalNanos,
                maxStalenessNanos, nanoClock);
    }

    /**
     * As the five-argument factory, with maximum staleness {@code max(1 day, 2 x refresh interval)},
     * capped at 7 days.
     *
     * @param source returns the current JWKS document; may throw on fetch failure
     * @param refreshIntervalNanos age after which the document is reloaded
     * @param minRefreshIntervalNanos minimum spacing of reloads, including those an unknown {@code kid} requests
     * @param nanoClock monotonic clock
     * @return the key set
     */
    public static JwksKeySet fromSource(Supplier<String> source, long refreshIntervalNanos,
                                        long minRefreshIntervalNanos, LongSupplier nanoClock) {
        return fromSource(source, refreshIntervalNanos, minRefreshIntervalNanos,
                defaultMaxStalenessNanos(refreshIntervalNanos), nanoClock);
    }

    /**
     * The default maximum staleness for a refresh interval: {@code max(1 day, 2 x refresh interval)},
     * capped at 7 days.
     *
     * @param refreshIntervalNanos refresh interval
     * @return maximum staleness in nanoseconds
     */
    public static long defaultMaxStalenessNanos(long refreshIntervalNanos) {
        long doubled = refreshIntervalNanos > WEEK_NANOS / 2 ? WEEK_NANOS : 2 * refreshIntervalNanos;
        return Math.min(WEEK_NANOS, Math.max(DAY_NANOS, doubled));
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
        return new JwksKeySet(null, new Snapshot(Map.copyOf(byKid), 0L), Long.MAX_VALUE, Long.MAX_VALUE,
                Long.MAX_VALUE, System::nanoTime);
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
     * Finds the key for {@code kid} in the snapshot held. Performs no I/O and takes no lock. A {@code kid}
     * the snapshot does not hold asks the refresher for an early reload, which the caller does not wait
     * for. Before the first successful load, and once the snapshot is older than the maximum staleness,
     * every key is refused.
     *
     * @param kid key id from the token header
     * @return the key, or empty when the issuer publishes no such key or the key set is not loaded or stale
     */
    public Optional<JwkKey> find(String kid) {
        Snapshot s = snapshot;
        if (source != null && (s == NOT_LOADED
                || nanoClock.getAsLong() - s.loadedAtNanos() >= maxStalenessNanos)) {
            return Optional.empty();
        }
        JwkKey key = s.keys().get(kid);
        if (key == null && source != null) {
            requestRefresh();
        }
        return Optional.ofNullable(key);
    }

    private void requestRefresh() {
        if (!refreshRequested.get() && refreshRequested.compareAndSet(false, true)) {
            Thread t = refresher;
            if (t != null) {
                LockSupport.unpark(t);
            }
        }
    }

    /**
     * Starts the background refresher and waits up to {@code awaitFirstLoadNanos} for its first attempt.
     * Idempotent; does nothing for a fixed key set or after {@link #stop()}.
     *
     * @param awaitFirstLoadNanos longest wait for the first load attempt to finish
     */
    public void start(long awaitFirstLoadNanos) {
        if (source == null) {
            return;
        }
        synchronized (lifecycle) {
            if (stopped || refresher != null) {
                return;
            }
            awaitNanos = awaitFirstLoadNanos;
            // The reference is published before the thread runs. A lookup writes the request flag and then
            // reads this reference; the refresher reads the flag only after this write. So a lookup that
            // finds no thread to unpark has set the flag before the refresher's first read of it, and a
            // lookup that finds the thread unparks it: a request is never both unseen and unsignalled.
            Thread thread = Thread.ofVirtual().name(REFRESHER_NAME).unstarted(this::run);
            refresher = thread;
            thread.start();
        }
        try {
            firstAttempt.await(awaitFirstLoadNanos, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Stops the refresher, interrupting a fetch in flight, and waits a bounded time for it to end.
     * Idempotent. The snapshot held keeps serving lookups until it passes the maximum staleness.
     */
    public void stop() {
        Thread t;
        long wait;
        synchronized (lifecycle) {
            stopped = true;
            t = refresher;
            wait = awaitNanos;
        }
        if (t == null) {
            return;
        }
        t.interrupt();
        LockSupport.unpark(t);
        try {
            t.join(Duration.ofNanos(Math.max(wait, 1_000_000L)));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void run() {
        try {
            while (!stopped) {
                Thread.interrupted();
                long now = nanoClock.getAsLong();
                long wait = nanosUntilDue(now);
                if (wait > 0) {
                    LockSupport.parkNanos(this, wait);
                    continue;
                }
                refreshRequested.set(false);
                attempt(now);
                firstAttempt.countDown();
            }
        } finally {
            firstAttempt.countDown();
        }
    }

    /** Nanoseconds until the refresher's next fetch is due at {@code now}; zero or less means due. */
    long nanosUntilDue(long now) {
        if (!attempted) {
            return 0L;
        }
        long early = lastAttemptNanos + minRefreshIntervalNanos - now;
        if (lastAttemptFailed || snapshot == NOT_LOADED) {
            return early;
        }
        long periodic = lastAttemptNanos + refreshIntervalNanos - now;
        return refreshRequested.get() ? Math.min(periodic, early) : periodic;
    }

    private void attempt(long now) {
        attempted = true;
        lastAttemptNanos = now;
        try {
            snapshot = new Snapshot(parse(source.get()), now);
            lastAttemptFailed = false;
        } catch (RuntimeException e) {
            lastAttemptFailed = true;
            LOG.log(System.Logger.Level.WARNING,
                    "JWKS reload failed; held keys stay in force until maximum staleness", e);
        }
    }

    /** Wakes the refresher to re-evaluate when it is due. */
    void wake() {
        Thread t = refresher;
        if (t != null) {
            LockSupport.unpark(t);
        }
    }

    boolean isRefresherAlive() {
        Thread t = refresher;
        return t != null && t.isAlive();
    }

    long maxStalenessNanos() {
        return maxStalenessNanos;
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
