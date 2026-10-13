package eu.exeris.caps.jwt.api;

/**
 * Immutable outcome of a JWT token validation attempt.
 *
 * @param status validation outcome status code; non-null
 * @param subject authenticated subject ({@code sub} claim) or null if unauthenticated
 * @param issuer token issuer ({@code iss} claim) or null if unauthenticated
 * @param tenantId tenant identifier ({@code tid} or {@code tenant_id} claim) or null
 * @param expiresAtSeconds expiration timestamp in epoch seconds ({@code exp} claim)
 * @param issuedAtSeconds issued-at timestamp in epoch seconds ({@code iat} claim)
 * @param errorMessage descriptive failure reason or null if valid
 *
 * @since 0.1.0
 */
public record JwtValidationResult(
        JwtValidationStatus status,
        String subject,
        String issuer,
        String tenantId,
        long expiresAtSeconds,
        long issuedAtSeconds,
        String errorMessage
) {

    /**
     * Indicates whether the token was fully validated and admitted.
     *
     * @return true if status is {@link JwtValidationStatus#VALID}
     */
    public boolean isValid() {
        return status == JwtValidationStatus.VALID;
    }

    /**
     * Creates a successful validation result.
     */
    public static JwtValidationResult valid(String subject, String issuer, String tenantId, long expiresAt, long issuedAt) {
        return new JwtValidationResult(JwtValidationStatus.VALID, subject, issuer, tenantId, expiresAt, issuedAt, null);
    }

    /**
     * Creates a failure validation result.
     */
    public static JwtValidationResult failure(JwtValidationStatus status, String errorMessage) {
        return new JwtValidationResult(status, null, null, null, 0L, 0L, errorMessage);
    }
}
