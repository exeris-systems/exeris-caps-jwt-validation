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

    /** Token is not a compact JWS, a segment is not Base64URL, or the header or claims are not a JSON object. */
    MALFORMED,

    /** Token has expired ({@code exp} is in the past beyond the permitted clock skew). */
    EXPIRED,

    /** Token is not yet valid ({@code nbf}, or {@code iat}, is in the future beyond the permitted clock skew). */
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
