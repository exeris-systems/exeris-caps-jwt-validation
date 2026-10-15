package eu.exeris.caps.jwt.api;

import eu.exeris.kernel.spi.security.PrincipalContext;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * The caller a verified access token identifies, as the admission filter records it in the request's
 * {@code RequestContext}.
 *
 * <p>Every field comes from a token whose signature, issuer, audience and validity window were checked;
 * none comes from the request body, a query parameter or an unverified header.
 *
 * @since 0.1.0
 */
public final class JwtPrincipal implements PrincipalContext {

    private final UUID subject;
    private final UUID tenant;
    private final UUID session;
    private final Set<String> roles;
    private final Set<String> scopes;
    private final String issuer;
    private final long expiresAtEpochSecond;

    /**
     * Creates the principal a validated token resolves to.
     *
     * @param subject {@code sub}; non-null
     * @param tenant the tenant claim, or null
     * @param session {@code sid}, or null
     * @param roles {@code roles}
     * @param scopes {@code scope} / {@code scp}
     * @param issuer {@code iss}; non-null
     * @param expiresAtEpochSecond {@code exp}
     */
    public JwtPrincipal(UUID subject, UUID tenant, UUID session, Set<String> roles, Set<String> scopes,
                        String issuer, long expiresAtEpochSecond) {
        this.subject = Objects.requireNonNull(subject, "subject");
        this.tenant = tenant;
        this.session = session;
        this.roles = Set.copyOf(roles);
        this.scopes = Set.copyOf(scopes);
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.expiresAtEpochSecond = expiresAtEpochSecond;
    }

    /**
     * Converts a valid result into a principal.
     *
     * @param result a {@link JwtValidationResult#isValid() valid} result
     * @return the principal, or empty when {@code sub}, the tenant claim or {@code sid} is not a UUID
     */
    public static Optional<JwtPrincipal> from(JwtValidationResult result) {
        if (!result.isValid()) {
            return Optional.empty();
        }
        try {
            UUID subject = uuid(result.subject());
            UUID tenant = result.tenantId() != null ? uuid(result.tenantId()) : null;
            UUID session = result.sessionId() != null ? uuid(result.sessionId()) : null;
            return Optional.of(new JwtPrincipal(subject, tenant, session, result.roles(), result.scopes(),
                    result.issuer(), result.expiresAtSeconds()));
        } catch (IllegalArgumentException notAUuid) {
            return Optional.empty();
        }
    }

    private static UUID uuid(String value) {
        UUID parsed = UUID.fromString(value);
        // UUID.fromString also accepts abbreviated forms; only the canonical 36-character form is an identity.
        if (!parsed.toString().equalsIgnoreCase(value)) {
            throw new IllegalArgumentException("not a canonical UUID");
        }
        return parsed;
    }

    @Override
    public UUID principalId() {
        return subject;
    }

    @Override
    public Optional<UUID> tenantId() {
        return Optional.ofNullable(tenant);
    }

    /**
     * Returns the session the token was issued for.
     *
     * @return {@code sid}, if the token carries one
     */
    public Optional<UUID> sessionId() {
        return Optional.ofNullable(session);
    }

    @Override
    public Set<String> roles() {
        return roles;
    }

    @Override
    public Set<String> scopes() {
        return scopes;
    }

    /**
     * Returns the issuer the token was minted by.
     *
     * @return the token's issuer
     */
    public String issuer() {
        return issuer;
    }

    /**
     * Returns the instant the token stops being valid.
     *
     * @return the token's {@code exp}, in epoch seconds
     */
    public long expiresAtEpochSecond() {
        return expiresAtEpochSecond;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof JwtPrincipal that
                && subject.equals(that.subject)
                && Objects.equals(tenant, that.tenant)
                && Objects.equals(session, that.session)
                && roles.equals(that.roles)
                && scopes.equals(that.scopes)
                && issuer.equals(that.issuer)
                && expiresAtEpochSecond == that.expiresAtEpochSecond;
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, tenant, session, roles, scopes, issuer, expiresAtEpochSecond);
    }

    @Override
    public String toString() {
        return "JwtPrincipal[subject=" + subject + ", tenant=" + tenant + ", session=" + session + "]";
    }
}
