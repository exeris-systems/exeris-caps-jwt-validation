package eu.exeris.caps.jwt.api;

/**
 * Status code returned by {@link JwtAdmissionPolicy} evaluation.
 *
 * @since 0.1.0
 */
public enum JwtValidationStatus {

    /** Token is well-formed, verified against a published key, within its validity window, and for this audience. */
    VALID,

    /** Authorization header or token is absent. */
    MISSING_TOKEN,

    /**
     * The input is structurally invalid: the {@code Authorization} scheme is not {@code Bearer}; the token is
     * longer than 8192 characters, is not a three-part compact JWS, or has a character outside Base64URL and
     * {@code '.'}; the header or claims are not a JSON object, or the header has no {@code alg} or lists
     * {@code crit}; or the tenant, {@code sid}, {@code roles}, {@code scope} or {@code scp} claim has the wrong type.
     */
    MALFORMED,

    /** Token has expired ({@code exp} is in the past beyond the permitted clock skew). */
    EXPIRED,

    /**
     * Token is not yet valid: {@code nbf} or {@code iat} is in the future beyond the permitted clock skew, or
     * {@code iat} is present and not an integer.
     */
    PREMATURE,

    /** Cryptographic signature check failed (token was forged or tampered with). */
    INVALID_SIGNATURE,

    /** Token issuer ({@code iss}) does not match the configured expected issuer. */
    UNAUTHORIZED_ISSUER,

    /** Token audience ({@code aud}) does not contain the configured expected audience. */
    UNAUTHORIZED_AUDIENCE,

    /** The header carries no {@code kid}, or the issuer publishes no key with that {@code kid}. */
    UNKNOWN_KEY,

    /** The header's {@code alg} is not the algorithm the key is bound to, or is not an accepted algorithm. */
    ALGORITHM_MISMATCH,

    /** A claim the policy requires ({@code exp}, {@code nbf}, {@code sub}) is absent or has the wrong type. */
    MISSING_CLAIM
}
