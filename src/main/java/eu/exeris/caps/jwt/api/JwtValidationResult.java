package eu.exeris.caps.jwt.api;

import java.util.Set;

/**
 * Immutable outcome of a JWT token validation attempt.
 *
 * <p>{@code errorMessage} is for the operator's log. It never goes into a response body, and it names no
 * claim value from the token.
 *
 * @param status validation outcome status code; non-null
 * @param subject authenticated subject ({@code sub} claim) or null if unauthenticated
 * @param issuer token issuer ({@code iss} claim) or null if unauthenticated
 * @param tenantId value of the configured tenant claim, or null when the token carries none
 * @param sessionId session id ({@code sid} claim) or null when the token carries none
 * @param roles roles ({@code roles} claim); empty when absent
 * @param scopes scopes ({@code scope}, space-delimited, or {@code scp}); empty when absent
 * @param expiresAtSeconds expiration timestamp in epoch seconds ({@code exp} claim)
 * @param issuedAtSeconds issued-at timestamp in epoch seconds ({@code iat} claim), 0 when absent
 * @param errorMessage failure reason for the log, or null if valid
 *
 * @since 0.1.0
 */
public record JwtValidationResult(
        JwtValidationStatus status,
        String subject,
        String issuer,
        String tenantId,
        String sessionId,
        Set<String> roles,
        Set<String> scopes,
        long expiresAtSeconds,
        long issuedAtSeconds,
        String errorMessage
) {

    public JwtValidationResult {
        roles = roles != null ? Set.copyOf(roles) : Set.of();
        scopes = scopes != null ? Set.copyOf(scopes) : Set.of();
    }

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
    public static JwtValidationResult valid(String subject, String issuer, String tenantId, String sessionId,
                                            Set<String> roles, Set<String> scopes, long expiresAt, long issuedAt) {
        return new JwtValidationResult(JwtValidationStatus.VALID, subject, issuer, tenantId, sessionId,
                roles, scopes, expiresAt, issuedAt, null);
    }

    /**
     * Creates a failure validation result.
     */
    public static JwtValidationResult failure(JwtValidationStatus status, String errorMessage) {
        return new JwtValidationResult(status, null, null, null, null, Set.of(), Set.of(), 0L, 0L, errorMessage);
    }
}
