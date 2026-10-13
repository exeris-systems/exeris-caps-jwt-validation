package eu.exeris.caps.jwt.api;

import eu.exeris.caps.jwt.internal.DefaultJwtAdmissionPolicy;
import eu.exeris.caps.jwt.internal.HttpJwksFetcher;
import eu.exeris.caps.jwt.internal.JwksKeySet;

import java.net.URI;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Factory and builder for {@link JwtAdmissionPolicy} instances.
 *
 * <p>A policy verifies EdDSA (Ed25519) tokens against the issuer's JWKS (ADR-099 obligation 8). RS256 is
 * accepted only when {@link Builder#acceptRs256()} is called. Every policy names exactly one key source, the
 * expected issuer and the expected audience; {@code exp} and {@code nbf} are always required.
 *
 * <p>{@link #fromProperties(Map, Supplier)} reads the same settings from configuration; its keys are the
 * {@code KEY_*} constants of this class.
 *
 * @since 0.1.0
 */
public final class JwtAdmissionPolicies {

    /** JWKS URI of the issuer; https, or http on a loopback host. */
    public static final String KEY_JWKS_URI = "exeris.caps.jwt.jwks-uri";
    /** Expected {@code iss}. Required. */
    public static final String KEY_ISSUER = "exeris.caps.jwt.issuer";
    /** Expected member of {@code aud}. Required. */
    public static final String KEY_AUDIENCE = "exeris.caps.jwt.audience";
    /** Comma-separated accepted algorithms: {@code EdDSA} (default), optionally {@code RS256}. */
    public static final String KEY_ALGORITHMS = "exeris.caps.jwt.algorithms";
    /** Permitted clock skew in seconds, applied to {@code exp}, {@code nbf} and {@code iat}; default 30, at most 300. */
    public static final String KEY_CLOCK_SKEW_SECONDS = "exeris.caps.jwt.clock-skew-seconds";
    /** Claim holding the tenant id, a single string the issuer omits when there is no tenant; default {@code tid}. */
    public static final String KEY_TENANT_CLAIM = "exeris.caps.jwt.tenant-claim";
    /** JWKS connect and response timeout in milliseconds; default 2000. */
    public static final String KEY_JWKS_TIMEOUT_MILLIS = "exeris.caps.jwt.jwks-timeout-millis";
    /** Age in seconds after which the JWKS is reloaded; default 300. */
    public static final String KEY_JWKS_REFRESH_SECONDS = "exeris.caps.jwt.jwks-refresh-seconds";
    /** Minimum seconds between JWKS reloads, including those an unknown {@code kid} triggers; default 30. */
    public static final String KEY_JWKS_MIN_REFRESH_SECONDS = "exeris.caps.jwt.jwks-min-refresh-seconds";

    /** Default name of the tenant claim. */
    public static final String DEFAULT_TENANT_CLAIM = "tid";

    private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(5);
    private static final Set<String> SUPPORTED_ALGORITHMS = Set.of("EdDSA", "RS256");

    private JwtAdmissionPolicies() {
    }

    /**
     * Creates a new builder for configuring a {@link JwtAdmissionPolicy}.
     *
     * @return builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builds a policy from configuration properties named by the {@code KEY_*} constants.
     *
     * @param properties configuration; {@link #KEY_ISSUER} and {@link #KEY_AUDIENCE} are required
     * @param inProcessJwks JWKS source used when {@link #KEY_JWKS_URI} is absent, for an issuer in the same
     *                      process; may be null
     * @return the policy
     * @throws IllegalStateException if the configuration names no key source or omits a required key
     */
    public static JwtAdmissionPolicy fromProperties(Map<String, String> properties, Supplier<String> inProcessJwks) {
        Objects.requireNonNull(properties, "properties");
        Builder builder = builder()
                .expectedIssuer(properties.get(KEY_ISSUER))
                .expectedAudience(properties.get(KEY_AUDIENCE))
                .tenantClaim(properties.getOrDefault(KEY_TENANT_CLAIM, DEFAULT_TENANT_CLAIM))
                .clockSkew(Duration.ofSeconds(longValue(properties, KEY_CLOCK_SKEW_SECONDS, 30)))
                .jwksTimeout(Duration.ofMillis(longValue(properties, KEY_JWKS_TIMEOUT_MILLIS, 2000)))
                .jwksRefreshInterval(Duration.ofSeconds(longValue(properties, KEY_JWKS_REFRESH_SECONDS, 300)))
                .jwksMinRefreshInterval(Duration.ofSeconds(longValue(properties, KEY_JWKS_MIN_REFRESH_SECONDS, 30)));
        String algorithms = properties.get(KEY_ALGORITHMS);
        if (algorithms != null) {
            Set<String> accepted = new LinkedHashSet<>();
            for (String alg : algorithms.split(",")) {
                if (!alg.isBlank()) {
                    accepted.add(alg.strip());
                }
            }
            builder.acceptedAlgorithms(accepted);
        }
        String uri = properties.get(KEY_JWKS_URI);
        if (uri != null && !uri.isBlank()) {
            builder.jwksUri(URI.create(uri.strip()));
        } else if (inProcessJwks != null) {
            builder.jwksSupplier(inProcessJwks);
        }
        return builder.build();
    }

    private static long longValue(Map<String, String> properties, String key, long fallback) {
        String value = properties.get(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Long.parseLong(value.strip());
        } catch (NumberFormatException e) {
            throw new IllegalStateException(key + " is not an integer", e);
        }
    }

    /**
     * Fluent builder for {@link JwtAdmissionPolicy}.
     */
    public static final class Builder {
        private URI jwksUri;
        private Supplier<String> jwksSupplier;
        private String staticJwks;
        private final List<JwksKeySet.JwkKey> fixedKeys = new ArrayList<>();
        private Set<String> acceptedAlgorithms = Set.of("EdDSA");
        private String expectedIssuer;
        private String expectedAudience;
        private Duration clockSkew = Duration.ofSeconds(30);
        private String tenantClaim = DEFAULT_TENANT_CLAIM;
        private Duration jwksTimeout = Duration.ofSeconds(2);
        private Duration jwksRefreshInterval = Duration.ofMinutes(5);
        private Duration jwksMinRefreshInterval = Duration.ofSeconds(30);
        private Clock clock = Clock.systemUTC();
        private LongSupplier nanoClock = System::nanoTime;

        private Builder() {
        }

        /** Fetches the issuer's JWKS from this URI, with the configured timeout. */
        public Builder jwksUri(URI uri) {
            this.jwksUri = Objects.requireNonNull(uri, "uri");
            return this;
        }

        /** Reads the issuer's JWKS from this source, e.g. an issuer running in the same process. */
        public Builder jwksSupplier(Supplier<String> supplier) {
            this.jwksSupplier = Objects.requireNonNull(supplier, "supplier");
            return this;
        }

        /** Uses this JWKS document and never reloads it. */
        public Builder jwks(String jwksJson) {
            this.staticJwks = Objects.requireNonNull(jwksJson, "jwksJson");
            return this;
        }

        /** Adds a fixed verification key; its type decides the one algorithm it verifies. */
        public Builder publicKey(String kid, PublicKey publicKey) {
            fixedKeys.add(JwksKeySet.bind(Objects.requireNonNull(kid, "kid"), Objects.requireNonNull(publicKey, "publicKey")));
            return this;
        }

        /** Also accepts RS256 tokens verified by an RSA key of at least 2048 bits. */
        public Builder acceptRs256() {
            Set<String> accepted = new LinkedHashSet<>(acceptedAlgorithms);
            accepted.add("RS256");
            this.acceptedAlgorithms = Set.copyOf(accepted);
            return this;
        }

        /** Replaces the accepted algorithms; each must be {@code EdDSA} or {@code RS256}. */
        public Builder acceptedAlgorithms(Set<String> algorithms) {
            this.acceptedAlgorithms = Set.copyOf(algorithms);
            return this;
        }

        public Builder expectedIssuer(String expectedIssuer) {
            this.expectedIssuer = expectedIssuer;
            return this;
        }

        public Builder expectedAudience(String expectedAudience) {
            this.expectedAudience = expectedAudience;
            return this;
        }

        /** Clock skew permitted on {@code exp}, {@code nbf} and {@code iat}; at most five minutes. */
        public Builder clockSkew(Duration clockSkew) {
            this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
            return this;
        }

        /** Name of the claim carrying the tenant id. */
        public Builder tenantClaim(String tenantClaim) {
            this.tenantClaim = Objects.requireNonNull(tenantClaim, "tenantClaim");
            return this;
        }

        public Builder jwksTimeout(Duration timeout) {
            this.jwksTimeout = Objects.requireNonNull(timeout, "timeout");
            return this;
        }

        public Builder jwksRefreshInterval(Duration interval) {
            this.jwksRefreshInterval = Objects.requireNonNull(interval, "interval");
            return this;
        }

        public Builder jwksMinRefreshInterval(Duration interval) {
            this.jwksMinRefreshInterval = Objects.requireNonNull(interval, "interval");
            return this;
        }

        /** Wall clock for {@code exp}, {@code nbf} and {@code iat}. */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /** Monotonic clock spacing JWKS reloads. */
        public Builder nanoClock(LongSupplier nanoClock) {
            this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock");
            return this;
        }

        public JwtAdmissionPolicy build() {
            int sources = (jwksUri != null ? 1 : 0) + (jwksSupplier != null ? 1 : 0)
                    + (staticJwks != null ? 1 : 0) + (fixedKeys.isEmpty() ? 0 : 1);
            if (sources != 1) {
                throw new IllegalStateException("Configure exactly one key source: a JWKS URI, a JWKS supplier, a JWKS document or fixed keys");
            }
            if (expectedIssuer == null || expectedIssuer.isBlank()) {
                throw new IllegalStateException("The expected issuer must be configured");
            }
            if (expectedAudience == null || expectedAudience.isBlank()) {
                throw new IllegalStateException("The expected audience must be configured");
            }
            if (clockSkew.isNegative() || clockSkew.compareTo(MAX_CLOCK_SKEW) > 0) {
                throw new IllegalStateException("Clock skew must be between 0 and " + MAX_CLOCK_SKEW.toSeconds() + " seconds");
            }
            if (acceptedAlgorithms.isEmpty() || !SUPPORTED_ALGORITHMS.containsAll(acceptedAlgorithms)) {
                throw new IllegalStateException("Accepted algorithms must be a non-empty subset of " + SUPPORTED_ALGORITHMS);
            }
            if (tenantClaim.isBlank()) {
                throw new IllegalStateException("The tenant claim name must not be blank");
            }
            JwksKeySet keySet;
            if (!fixedKeys.isEmpty()) {
                keySet = JwksKeySet.fixed(fixedKeys);
            } else if (staticJwks != null) {
                keySet = JwksKeySet.fixed(List.copyOf(JwksKeySet.parse(staticJwks).values()));
            } else {
                Supplier<String> source = jwksSupplier != null ? jwksSupplier : new HttpJwksFetcher(jwksUri, jwksTimeout);
                keySet = JwksKeySet.fromSource(source, jwksRefreshInterval.toNanos(),
                        jwksMinRefreshInterval.toNanos(), nanoClock);
            }
            return new DefaultJwtAdmissionPolicy(keySet, acceptedAlgorithms, expectedIssuer.strip(),
                    expectedAudience.strip(), clockSkew.toSeconds(), tenantClaim, clock);
        }
    }
}
