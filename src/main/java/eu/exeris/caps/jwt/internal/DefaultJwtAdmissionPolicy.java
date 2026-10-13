package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtValidationResult;
import eu.exeris.caps.jwt.api.JwtValidationStatus;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.util.function.Function;

/**
 * High-performance, zero-allocation default implementation of {@link JwtAdmissionPolicy}.
 *
 * <p>Supports both HMAC-SHA256 (HS256) and Ed25519 (EdDSA) verification against
 * JWKS documents, with strict algorithm pinning and verification prior to signature parsing (ADR-099).
 *
 * @since 0.1.0
 */
public final class DefaultJwtAdmissionPolicy implements JwtAdmissionPolicy {

    private final HmacSha256Validator hmacValidator;
    private final Function<String, PublicKey> keyResolver;
    private final String pinnedAlgorithm;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final long leewaySeconds;
    private final LockFreeJwtCache cache;
    private final Clock clock;

    public DefaultJwtAdmissionPolicy(
            byte[] secretBytes,
            String expectedIssuer,
            String expectedAudience,
            Duration leeway,
            int cacheCapacity,
            Clock clock
    ) {
        this(secretBytes, null, "HS256", expectedIssuer, expectedAudience, leeway, cacheCapacity, clock);
    }

    public DefaultJwtAdmissionPolicy(
            byte[] secretBytes,
            Function<String, PublicKey> keyResolver,
            String pinnedAlgorithm,
            String expectedIssuer,
            String expectedAudience,
            Duration leeway,
            int cacheCapacity,
            Clock clock
    ) {
        this.hmacValidator = (secretBytes != null && secretBytes.length > 0) ? new HmacSha256Validator(secretBytes) : null;
        this.keyResolver = keyResolver;
        this.pinnedAlgorithm = pinnedAlgorithm;
        this.expectedIssuer = (expectedIssuer != null && !expectedIssuer.isBlank()) ? expectedIssuer : null;
        this.expectedAudience = (expectedAudience != null && !expectedAudience.isBlank()) ? expectedAudience : null;
        this.leewaySeconds = leeway != null ? Math.max(0, leeway.toSeconds()) : 0L;
        this.cache = cacheCapacity > 0 ? new LockFreeJwtCache(cacheCapacity) : null;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public JwtValidationResult validate(CharSequence authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.length() == 0) {
            return JwtValidationResult.failure(JwtValidationStatus.MISSING_TOKEN, "Missing Authorization header");
        }

        int tokenStart = skipBearerPrefix(authorizationHeader);
        if (tokenStart < 0) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Invalid authorization scheme (expected Bearer)");
        }

        return validateTokenSlice(authorizationHeader, tokenStart, authorizationHeader.length());
    }

    @Override
    public JwtValidationResult validateToken(CharSequence rawToken) {
        if (rawToken == null || rawToken.length() == 0) {
            return JwtValidationResult.failure(JwtValidationStatus.MISSING_TOKEN, "Token is empty");
        }
        return validateTokenSlice(rawToken, 0, rawToken.length());
    }

    private JwtValidationResult validateTokenSlice(CharSequence token, int start, int end) {
        int dot1 = indexOf(token, '.', start, end);
        if (dot1 < 0) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Malformed JWT: missing first dot");
        }
        int dot2 = indexOf(token, '.', dot1 + 1, end);
        if (dot2 < 0) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Malformed JWT: missing second dot");
        }
        if (indexOf(token, '.', dot2 + 1, end) >= 0) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Malformed JWT: contains more than two dots");
        }

        // 1. Decode header and extract algorithm & kid
        byte[] headerBytes = Base64UrlDecoder.decodeToBytes(token, start, dot1);
        if (headerBytes == null) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Malformed JWT: header is not valid Base64URL");
        }

        JsonHeaderScanner.ParsedHeader header = JsonHeaderScanner.scan(headerBytes);
        if (header == null || header.alg() == null || header.alg().isBlank()) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Malformed JWT: missing algorithm header");
        }

        String alg = header.alg();
        if ("none".equalsIgnoreCase(alg)) {
            return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "Algorithm 'none' is rejected");
        }

        // 2. Strict algorithm pinning enforcement (ADR-099 Zobowiązanie 8)
        if (pinnedAlgorithm != null && !pinnedAlgorithm.equalsIgnoreCase(alg)) {
            return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE,
                    "Algorithm mismatch: pinned to '" + pinnedAlgorithm + "' but token specified '" + alg + "'");
        }

        long nowSeconds = clock.instant().getEpochSecond();

        // 3. Check lock-free signature cache (keyed on entire token to prevent payload tampering)
        long tokenHash = 0L;
        if (cache != null) {
            tokenHash = ZeroAllocHasher.hashSubSequence(token, start, end);
            JwtValidationResult cached = cache.get(tokenHash, nowSeconds);
            if (cached != null) {
                return cached;
            }
        }

        // 4. Decode payload
        byte[] payloadBytes = Base64UrlDecoder.decodeToBytes(token, dot1 + 1, dot2);
        if (payloadBytes == null) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Malformed JWT: payload is not valid Base64URL");
        }

        // Scan standard claims
        JsonClaimsScanner.ParsedClaims claims = JsonClaimsScanner.scan(payloadBytes);
        if (claims == null) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Malformed JWT: payload is not valid JSON");
        }

        // Fast-path claims checks before expensive crypto
        if (claims.expiresAt() > 0 && claims.expiresAt() + leewaySeconds < nowSeconds) {
            return JwtValidationResult.failure(JwtValidationStatus.EXPIRED, "Token expired at epoch " + claims.expiresAt());
        }

        if (claims.notBefore() > 0 && claims.notBefore() - leewaySeconds > nowSeconds) {
            return JwtValidationResult.failure(JwtValidationStatus.PREMATURE, "Token not valid before epoch " + claims.notBefore());
        }

        if (expectedIssuer != null && !expectedIssuer.equals(claims.issuer())) {
            return JwtValidationResult.failure(JwtValidationStatus.UNAUTHORIZED_ISSUER,
                    "Expected issuer '" + expectedIssuer + "' but got '" + claims.issuer() + "'");
        }

        if (expectedAudience != null && !expectedAudience.equals(claims.audience())) {
            return JwtValidationResult.failure(JwtValidationStatus.UNAUTHORIZED_AUDIENCE,
                    "Expected audience '" + expectedAudience + "' but got '" + claims.audience() + "'");
        }

        // 5. Decode signature bytes
        byte[] signatureBytes = Base64UrlDecoder.decodeToBytes(token, dot2 + 1, end);
        if (signatureBytes == null) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Malformed JWT: signature is not valid Base64URL");
        }

        // 6. Cryptographic signature verification based on algorithm
        if ("EdDSA".equalsIgnoreCase(alg)) {
            if (keyResolver == null) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "EdDSA algorithm not configured on policy");
            }
            if (header.kid() == null || header.kid().isBlank()) {
                if (keyResolver.apply(null) == null) {
                    return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "kid header missing for asymmetric token");
                }
            }
            PublicKey publicKey = keyResolver.apply(header.kid());
            if (publicKey == null) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE,
                        "Unknown or unresolvable key id: " + (header.kid() != null ? header.kid() : "<unspecified>"));
            }
            if (signatureBytes.length != 64) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE,
                        "Ed25519 signature must be exactly 64 bytes, got " + signatureBytes.length);
            }
            try {
                Signature sig = Signature.getInstance("Ed25519");
                sig.initVerify(publicKey);
                updateSignature(sig, token, start, dot2);
                if (!sig.verify(signatureBytes)) {
                    return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "Ed25519 signature verification failed");
                }
            } catch (Exception ex) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "Ed25519 signature verification error: " + ex.getMessage());
            }
        } else if ("RS256".equalsIgnoreCase(alg)) {
            if (keyResolver == null) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "RS256 algorithm not configured on policy");
            }
            if (header.kid() == null || header.kid().isBlank()) {
                if (keyResolver.apply(null) == null) {
                    return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "kid header missing for asymmetric token");
                }
            }
            PublicKey publicKey = keyResolver.apply(header.kid());
            if (publicKey == null) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE,
                        "Unknown or unresolvable key id: " + (header.kid() != null ? header.kid() : "<unspecified>"));
            }
            if (!(publicKey instanceof java.security.interfaces.RSAPublicKey rsaPub)) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "Key for RS256 must be an RSAPublicKey");
            }
            int expectedKeyBytes = (rsaPub.getModulus().bitLength() + 7) / 8;
            if (signatureBytes.length != expectedKeyBytes) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE,
                        "RS256 signature length mismatch: expected " + expectedKeyBytes + " bytes, got " + signatureBytes.length);
            }
            try {
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(publicKey);
                updateSignature(sig, token, start, dot2);
                if (!sig.verify(signatureBytes)) {
                    return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "RS256 signature verification failed");
                }
            } catch (Exception ex) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "RS256 signature verification error: " + ex.getMessage());
            }
        } else if ("ES256".equalsIgnoreCase(alg)) {
            if (keyResolver == null) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "ES256 algorithm not configured on policy");
            }
            if (header.kid() == null || header.kid().isBlank()) {
                if (keyResolver.apply(null) == null) {
                    return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "kid header missing for asymmetric token");
                }
            }
            PublicKey publicKey = keyResolver.apply(header.kid());
            if (publicKey == null) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE,
                        "Unknown or unresolvable key id: " + (header.kid() != null ? header.kid() : "<unspecified>"));
            }
            if (!(publicKey instanceof java.security.interfaces.ECPublicKey)) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "Key for ES256 must be an ECPublicKey");
            }
            if (signatureBytes.length != 64) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE,
                        "ES256 P1363 signature must be exactly 64 bytes (R||S), got " + signatureBytes.length);
            }
            try {
                Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
                sig.initVerify(publicKey);
                updateSignature(sig, token, start, dot2);
                if (!sig.verify(signatureBytes)) {
                    return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "ES256 signature verification failed");
                }
            } catch (Exception ex) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "ES256 signature verification error: " + ex.getMessage());
            }
        } else if ("HS256".equalsIgnoreCase(alg)) {
            if (hmacValidator == null) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "HMAC-SHA256 algorithm not configured on policy");
            }
            boolean validSig = hmacValidator.verify(token, start, dot2, signatureBytes);
            if (!validSig) {
                return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "HMAC-SHA256 signature verification failed");
            }
        } else {
            return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "Unsupported JWT algorithm: " + alg);
        }

        JwtValidationResult result = JwtValidationResult.valid(
                claims.subject(),
                claims.issuer(),
                claims.tenantId(),
                claims.expiresAt(),
                claims.issuedAt()
        );

        if (cache != null && tokenHash != 0L) {
            cache.put(tokenHash, result);
        }

        return result;
    }

    private static int skipBearerPrefix(CharSequence h) {
        int len = h.length();
        int i = 0;
        while (i < len && h.charAt(i) == ' ') {
            i++;
        }
        if (len - i < 7) {
            return -1;
        }
        char c0 = h.charAt(i);
        char c1 = h.charAt(i + 1);
        char c2 = h.charAt(i + 2);
        char c3 = h.charAt(i + 3);
        char c4 = h.charAt(i + 4);
        char c5 = h.charAt(i + 5);
        char c6 = h.charAt(i + 6);

        boolean isBearer = (c0 == 'B' || c0 == 'b') &&
                (c1 == 'e' || c1 == 'E') &&
                (c2 == 'a' || c2 == 'A') &&
                (c3 == 'r' || c3 == 'R') &&
                (c4 == 'e' || c4 == 'E') &&
                (c5 == 'r' || c5 == 'R') &&
                c6 == ' ';

        if (!isBearer) {
            return -1;
        }
        i += 7;
        while (i < len && h.charAt(i) == ' ') {
            i++;
        }
        return i;
    }

    private static final int CHUNK_SIZE = 512;

    private static void updateSignature(Signature sig, CharSequence input, int start, int end) throws Exception {
        int len = end - start;
        byte[] buf = new byte[Math.min(len, CHUNK_SIZE)];
        int pos = 0;
        for (int i = 0; i < len; i++) {
            char c = input.charAt(start + i);
            buf[pos++] = (byte) (c <= 127 ? c : '?');
            if (pos == buf.length) {
                sig.update(buf, 0, pos);
                pos = 0;
            }
        }
        if (pos > 0) {
            sig.update(buf, 0, pos);
        }
    }

    private static int indexOf(CharSequence cs, char target, int start, int end) {
        for (int i = start; i < end; i++) {
            if (cs.charAt(i) == target) {
                return i;
            }
        }
        return -1;
    }
}
