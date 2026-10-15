package eu.exeris.caps.jwt.api;

/**
 * Contract for edge JWT admission and token validation policy.
 *
 * <p>A policy verifies a bearer token against the issuer's keys; an {@link AdmissionHostBinding} installs it
 * in a host, today the Service Boundary filter chain ({@link JwtServiceBoundaryBinding}). Every call verifies
 * the signature; nothing about a token is cached.
 *
 * <p><b>Thread-safety:</b> a host calls the policy for each request, concurrently, so an implementation must be
 * safe for concurrent use. The default implementation (see {@link JwtAdmissionPolicies}) keeps no per-call
 * state; the key set it shares is published through volatile fields, and a JWKS reload runs under a lock, so
 * concurrent callers that find the keys stale or a {@code kid} unknown wait for one reload instead of starting
 * their own.
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
