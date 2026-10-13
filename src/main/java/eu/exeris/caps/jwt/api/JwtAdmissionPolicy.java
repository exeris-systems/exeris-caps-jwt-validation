package eu.exeris.caps.jwt.api;

/**
 * Contract for edge JWT admission and token validation policy.
 *
 * <p>Participates in the Gateway policy pipeline to authenticate inbound requests
 * against cryptographic tokens with zero-allocation parsing and bounded signature caching.
 *
 * @since 0.1.0
 */
public interface JwtAdmissionPolicy {

    /**
     * Validates an HTTP {@code Authorization} header value (e.g. {@code "Bearer <token>"}).
     *
     * @param authorizationHeader raw authorization header value; may be null or empty
     * @return validation result; non-null
     */
    JwtValidationResult validate(CharSequence authorizationHeader);

    /**
     * Validates a raw compact JWT string ({@code <header>.<payload>.<signature>}).
     *
     * @param rawToken raw JWT string; non-null
     * @return validation result; non-null
     */
    JwtValidationResult validateToken(CharSequence rawToken);
}
