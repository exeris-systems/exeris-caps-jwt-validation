package eu.exeris.caps.jwt.api;

import eu.exeris.caps.jwt.internal.DefaultJwtAdmissionPolicy;
import eu.exeris.caps.jwt.internal.JwksKeyResolver;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Factory and builder for creating {@link JwtAdmissionPolicy} instances.
 *
 * <p>Supports HMAC-SHA256 (HS256) and Ed25519 (EdDSA) verification against
 * JWKS documents and pinned keys (ADR-099).
 *
 * @since 0.1.0
 */
public final class JwtAdmissionPolicies {

    private JwtAdmissionPolicies() {
    }

    /**
     * Creates a new builder for configuring a {@link JwtAdmissionPolicy}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a simple HMAC-SHA256 policy with default parameters.
     *
     * @param secret raw UTF-8 secret string
     */
    public static JwtAdmissionPolicy forHmacSecret(String secret) {
        return builder().secret(secret).build();
    }

    /**
     * Creates a simple HMAC-SHA256 policy with raw secret bytes.
     *
     * @param secretBytes raw secret bytes
     */
    public static JwtAdmissionPolicy forHmacSecret(byte[] secretBytes) {
        return builder().secret(secretBytes).build();
    }

    /**
     * Creates an EdDSA / Ed25519 policy verifying tokens against a JWKS JSON document.
     *
     * @param jwksJson raw JWKS JSON string
     */
    public static JwtAdmissionPolicy forJwks(String jwksJson) {
        return builder().jwks(jwksJson).pinnedAlgorithm("EdDSA").build();
    }

    /**
     * Creates an EdDSA / Ed25519 policy verifying tokens against a dynamic JWKS supplier.
     *
     * @param jwksSupplier dynamic JWKS supplier
     */
    public static JwtAdmissionPolicy forJwks(Supplier<String> jwksSupplier) {
        return builder().jwksSupplier(jwksSupplier).pinnedAlgorithm("EdDSA").build();
    }

    /**
     * Creates an EdDSA / Ed25519 policy verifying tokens against a single public key.
     *
     * @param publicKey Ed25519 public key
     */
    public static JwtAdmissionPolicy forEd25519(PublicKey publicKey) {
        return builder().publicKey(publicKey, "EdDSA").build();
    }

    /**
     * Creates an RS256 policy verifying tokens against an RSA public key.
     *
     * @param publicKey RSA public key
     */
    public static JwtAdmissionPolicy forRs256(PublicKey publicKey) {
        return builder().publicKey(publicKey, "RS256").build();
    }

    /**
     * Creates an ES256 policy verifying tokens against an EC public key (secp256r1 / P-256).
     *
     * @param publicKey EC public key
     */
    public static JwtAdmissionPolicy forEs256(PublicKey publicKey) {
        return builder().publicKey(publicKey, "ES256").build();
    }

    /**
     * Creates a policy verifying tokens against a public key with the specified algorithm.
     */
    public static JwtAdmissionPolicy forPublicKey(PublicKey publicKey, String algorithm) {
        return builder().publicKey(publicKey, algorithm).build();
    }

    /**
     * Fluent builder for {@link JwtAdmissionPolicy}.
     */
    public static final class Builder {
        private byte[] secretBytes;
        private Function<String, PublicKey> keyResolver;
        private String pinnedAlgorithm;
        private String expectedIssuer;
        private String expectedAudience;
        private Duration leeway = Duration.ofSeconds(30);
        private int cacheCapacity = 16384;
        private Clock clock = Clock.systemUTC();

        private Builder() {
        }

        public Builder secret(byte[] secretBytes) {
            this.secretBytes = secretBytes != null ? secretBytes.clone() : null;
            return this;
        }

        public Builder secret(String secretString) {
            this.secretBytes = secretString != null ? secretString.getBytes(StandardCharsets.UTF_8) : null;
            return this;
        }

        public Builder jwks(String jwksJson) {
            Objects.requireNonNull(jwksJson, "jwksJson");
            this.keyResolver = JwksKeyResolver.fromStaticJwks(jwksJson);
            if (this.pinnedAlgorithm == null) {
                this.pinnedAlgorithm = "EdDSA";
            }
            return this;
        }

        public Builder jwksSupplier(Supplier<String> jwksSupplier) {
            Objects.requireNonNull(jwksSupplier, "jwksSupplier");
            this.keyResolver = JwksKeyResolver.fromSupplier(jwksSupplier);
            if (this.pinnedAlgorithm == null) {
                this.pinnedAlgorithm = "EdDSA";
            }
            return this;
        }

        public Builder publicKey(PublicKey publicKey) {
            Objects.requireNonNull(publicKey, "publicKey");
            this.keyResolver = JwksKeyResolver.fromSingleKey(publicKey);
            if (this.pinnedAlgorithm == null) {
                if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
                    this.pinnedAlgorithm = "RS256";
                } else if (publicKey instanceof java.security.interfaces.ECPublicKey) {
                    this.pinnedAlgorithm = "ES256";
                } else {
                    this.pinnedAlgorithm = "EdDSA";
                }
            }
            return this;
        }

        public Builder publicKey(PublicKey publicKey, String algorithm) {
            Objects.requireNonNull(publicKey, "publicKey");
            this.keyResolver = JwksKeyResolver.fromSingleKey(publicKey);
            this.pinnedAlgorithm = algorithm;
            return this;
        }

        public Builder keyResolver(Function<String, PublicKey> resolver) {
            this.keyResolver = resolver;
            return this;
        }

        public Builder pinnedAlgorithm(String pinnedAlgorithm) {
            this.pinnedAlgorithm = pinnedAlgorithm;
            return this;
        }

        public Builder algorithm(String algorithm) {
            this.pinnedAlgorithm = algorithm;
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

        public Builder leeway(Duration leeway) {
            this.leeway = leeway;
            return this;
        }

        public Builder cacheCapacity(int cacheCapacity) {
            this.cacheCapacity = cacheCapacity;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public JwtAdmissionPolicy build() {
            if ((secretBytes == null || secretBytes.length == 0) && keyResolver == null) {
                throw new IllegalStateException("JWT secret or public key/JWKS must be configured");
            }
            String effPinnedAlg = pinnedAlgorithm;
            if (effPinnedAlg == null) {
                if (keyResolver != null && (secretBytes == null || secretBytes.length == 0)) {
                    effPinnedAlg = "EdDSA";
                } else if (secretBytes != null && secretBytes.length > 0 && keyResolver == null) {
                    effPinnedAlg = "HS256";
                }
            }
            return new DefaultJwtAdmissionPolicy(
                    secretBytes,
                    keyResolver,
                    effPinnedAlg,
                    expectedIssuer,
                    expectedAudience,
                    leeway,
                    cacheCapacity,
                    clock
            );
        }
    }
}
