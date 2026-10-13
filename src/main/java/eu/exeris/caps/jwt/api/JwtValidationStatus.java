package eu.exeris.caps.jwt.api;

/**
 * Status code returned by {@link JwtAdmissionPolicy} evaluation.
 *
 * @since 0.1.0
 */
public enum JwtValidationStatus {

    /** Token is syntactically valid, untampered, within validity window, and matches criteria. */
    VALID,

    /** Authorization header or token is absent. */
    MISSING_TOKEN,

    /** Token does not conform to 3-part compact JWT format or JSON claims are malformed. */
    MALFORMED,

    /** Token has expired ({@code exp} timestamp is in the past). */
    EXPIRED,

    /** Token is not yet valid ({@code nbf} timestamp is in the future). */
    PREMATURE,

    /** Cryptographic signature check failed (token was forged or tampered with). */
    INVALID_SIGNATURE,

    /** Token issuer ({@code iss}) does not match the configured expected issuer. */
    UNAUTHORIZED_ISSUER,

    /** Token audience ({@code aud}) does not match the configured expected audience. */
    UNAUTHORIZED_AUDIENCE
}
