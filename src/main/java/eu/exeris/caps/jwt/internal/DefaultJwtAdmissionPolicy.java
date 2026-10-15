package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtValidationResult;
import eu.exeris.caps.jwt.api.JwtValidationStatus;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Default {@link JwtAdmissionPolicy}: verifies a compact JWS against the issuer's published keys.
 *
 * <p>The checks run in a fixed order, and each one runs only after every check before it passed:
 * <ol>
 *   <li>parse: three Base64URL segments, the header a JSON object with an {@code alg} and no {@code crit};</li>
 *   <li>{@code kid}: present in the header;</li>
 *   <li>key: the issuer's key with that {@code kid}, from the JWKS;</li>
 *   <li>algorithm: the header's {@code alg} must equal the algorithm the key is bound to, and be accepted;</li>
 *   <li>signature, with the key and that algorithm only;</li>
 *   <li>the claims, read only now and in this order: {@code iss}, {@code aud}, {@code exp} and {@code nbf}
 *       (both required), {@code iat} an integer and not in the future, each time claim with the same bounded
 *       clock skew; then a non-empty {@code sub} (else {@code MISSING_CLAIM}); then the tenant, {@code sid},
 *       {@code roles}, {@code scope} and {@code scp} claims, each of which, when present, must have its
 *       expected type (else {@code MALFORMED}).</li>
 * </ol>
 * The algorithm is never taken from the token on its own, so a token cannot choose how it is verified.
 * Nothing about a token is cached: every call verifies the signature.
 *
 * @since 0.1.0
 */
public final class DefaultJwtAdmissionPolicy implements JwtAdmissionPolicy {

    /** Upper bound on a compact token's length; anything longer is refused before decoding. */
    public static final int MAX_TOKEN_LENGTH = 8192;

    private final JwksKeySet keySet;
    private final Set<String> acceptedAlgorithms;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final long skewSeconds;
    private final String tenantClaim;
    private final Clock clock;

    public DefaultJwtAdmissionPolicy(JwksKeySet keySet, Set<String> acceptedAlgorithms, String expectedIssuer,
                                     String expectedAudience, long skewSeconds, String tenantClaim, Clock clock) {
        this.keySet = Objects.requireNonNull(keySet, "keySet");
        this.acceptedAlgorithms = Set.copyOf(acceptedAlgorithms);
        this.expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer");
        this.expectedAudience = Objects.requireNonNull(expectedAudience, "expectedAudience");
        this.skewSeconds = skewSeconds;
        this.tenantClaim = Objects.requireNonNull(tenantClaim, "tenantClaim");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public JwtValidationResult validate(CharSequence authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isEmpty()) {
            return JwtValidationResult.failure(JwtValidationStatus.MISSING_TOKEN, "Missing Authorization header");
        }
        String header = authorizationHeader.toString();
        if (header.length() < 8 || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, "Authorization scheme is not Bearer");
        }
        return validateToken(header.substring(7).strip());
    }

    @Override
    public JwtValidationResult validateToken(CharSequence rawToken) {
        if (rawToken == null || rawToken.isEmpty()) {
            return JwtValidationResult.failure(JwtValidationStatus.MISSING_TOKEN, "Token is empty");
        }
        if (rawToken.length() > MAX_TOKEN_LENGTH) {
            return malformed("Token exceeds " + MAX_TOKEN_LENGTH + " characters");
        }
        String token = rawToken.toString();
        if (!isCompactSerialization(token)) {
            return malformed("Token contains characters outside Base64URL and '.'");
        }

        // 1. Parse: exactly three non-empty segments, header is a JSON object.
        int dot1 = token.indexOf('.');
        int dot2 = dot1 < 0 ? -1 : token.indexOf('.', dot1 + 1);
        if (dot1 <= 0 || dot2 < 0 || dot2 == dot1 + 1 || dot2 == token.length() - 1
                || token.indexOf('.', dot2 + 1) >= 0) {
            return malformed("Token is not a three-part compact JWS");
        }
        JwsHeaderScanner.Header header;
        byte[] signatureBytes;
        try {
            header = JwsHeaderScanner.scan(decodeSegment(token, 0, dot1));
            signatureBytes = Base64.getUrlDecoder().decode(token.substring(dot2 + 1));
        } catch (IllegalArgumentException e) {
            return malformed("Token header or signature is not valid Base64URL JSON");
        }
        String alg = header.alg();
        if (alg == null || alg.isEmpty()) {
            return malformed("Token header has no alg");
        }
        if (header.critical()) {
            return malformed("Token header lists critical extensions, none of which are supported");
        }

        // 2. kid.
        String kid = header.kid();
        if (kid == null || kid.isEmpty()) {
            return JwtValidationResult.failure(JwtValidationStatus.UNKNOWN_KEY, "Token header has no kid");
        }

        // 3. Key, from the issuer's JWKS.
        Optional<JwksKeySet.JwkKey> found = keySet.find(kid);
        if (found.isEmpty()) {
            return JwtValidationResult.failure(JwtValidationStatus.UNKNOWN_KEY, "No published key matches the token's kid");
        }
        JwksKeySet.JwkKey key = found.get();

        // 4. Algorithm pinned to the key, before any signature work.
        if (!key.algorithm().equals(alg) || !acceptedAlgorithms.contains(key.algorithm())) {
            return JwtValidationResult.failure(JwtValidationStatus.ALGORITHM_MISMATCH,
                    "Token alg is not the algorithm its key is bound to, or is not accepted");
        }

        // 5. Signature.
        if (!verifySignature(key, token.substring(0, dot2).getBytes(StandardCharsets.US_ASCII), signatureBytes)) {
            return JwtValidationResult.failure(JwtValidationStatus.INVALID_SIGNATURE, "Signature verification failed");
        }

        // 6. Claims, trusted only from here on.
        JwtClaimsScanner.Claims claims;
        try {
            claims = JwtClaimsScanner.scan(decodeSegment(token, dot1 + 1, dot2), expectedAudience, tenantClaim);
        } catch (IllegalArgumentException e) {
            return malformed("Token claims are not a JSON object");
        }
        return checkClaims(claims);
    }

    private JwtValidationResult checkClaims(JwtClaimsScanner.Claims claims) {
        if (!expectedIssuer.equals(claims.issuer)) {
            return JwtValidationResult.failure(JwtValidationStatus.UNAUTHORIZED_ISSUER, "Token iss is not the expected issuer");
        }
        if (!claims.audienceMatches) {
            return JwtValidationResult.failure(JwtValidationStatus.UNAUTHORIZED_AUDIENCE, "Token aud does not contain the expected audience");
        }
        if (!claims.hasExp) {
            return JwtValidationResult.failure(JwtValidationStatus.MISSING_CLAIM, "Token has no integer exp");
        }
        long exp = claims.exp;
        long now = clock.instant().getEpochSecond();
        if (now > exp + skewSeconds) {
            return JwtValidationResult.failure(JwtValidationStatus.EXPIRED, "Token has expired");
        }
        if (!claims.hasNbf) {
            return JwtValidationResult.failure(JwtValidationStatus.MISSING_CLAIM, "Token has no integer nbf");
        }
        if (claims.nbf - skewSeconds > now) {
            return JwtValidationResult.failure(JwtValidationStatus.PREMATURE, "Token nbf is in the future");
        }
        if (claims.iatWrong || (claims.hasIat && claims.iat - skewSeconds > now)) {
            return JwtValidationResult.failure(JwtValidationStatus.PREMATURE, "Token iat is in the future or not an integer");
        }
        String sub = claims.subject;
        if (sub == null || sub.isEmpty()) {
            return JwtValidationResult.failure(JwtValidationStatus.MISSING_CLAIM, "Token has no sub");
        }
        if (claims.tenantWrong || claims.sessionIdWrong) {
            return malformed("Token tenant or sid claim is not a string");
        }
        Set<String> scopes = scopes(claims);
        if (claims.rolesWrong || scopes == null) {
            return malformed("Token roles or scope claim has the wrong type");
        }
        return JwtValidationResult.valid(sub, expectedIssuer, claims.tenant, claims.sessionId, claims.roles, scopes,
                exp, claims.hasIat ? claims.iat : 0L);
    }

    private static Set<String> scopes(JwtClaimsScanner.Claims claims) {
        if (claims.scopeString != null) {
            Set<String> out = new LinkedHashSet<>();
            for (String part : claims.scopeString.split(" ")) {
                if (!part.isEmpty()) {
                    out.add(part);
                }
            }
            return out;
        }
        if (claims.scopeWrong) {
            return null;
        }
        return claims.scpWrong ? null : claims.scp;
    }

    private static boolean verifySignature(JwksKeySet.JwkKey key, byte[] signingInput, byte[] signature) {
        String jcaAlgorithm = switch (key.algorithm()) {
            case JwksKeySet.EDDSA -> "Ed25519";
            case JwksKeySet.RS256 -> "SHA256withRSA";
            default -> null;
        };
        if (jcaAlgorithm == null) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(jcaAlgorithm);
            verifier.initVerify(key.publicKey());
            verifier.update(signingInput);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    private static byte[] decodeSegment(String token, int start, int end) {
        return Base64.getUrlDecoder().decode(token.substring(start, end));
    }

    private static boolean isCompactSerialization(String token) {
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static JwtValidationResult malformed(String message) {
        return JwtValidationResult.failure(JwtValidationStatus.MALFORMED, message);
    }
}
