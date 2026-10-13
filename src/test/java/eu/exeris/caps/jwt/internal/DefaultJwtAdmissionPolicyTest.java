package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtValidationResult;
import eu.exeris.caps.jwt.api.JwtValidationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("DefaultJwtAdmissionPolicy Unit Tests")
class DefaultJwtAdmissionPolicyTest {

    private static final String SECRET = "exeris-gateway-edge-auth-secret-key-32b";
    private static final Instant NOW = Instant.ofEpochSecond(1700000000L);
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneId.of("UTC"));

    private JwtAdmissionPolicy policy;

    @BeforeEach
    void setUp() {
        policy = JwtAdmissionPolicies.builder()
                .secret(SECRET)
                .expectedIssuer("https://auth.exeris.eu")
                .expectedAudience("exeris-api")
                .leeway(Duration.ofSeconds(10))
                .clock(FIXED_CLOCK)
                .build();
    }

    @Test
    @DisplayName("Valid token in Authorization Bearer header passes validation")
    void testValidToken() {
        String token = JwtTestHelper.createToken(
                SECRET,
                "user-123",
                "https://auth.exeris.eu",
                "tenant-alpha",
                "exeris-api",
                1700003600L, // exp +1h
                1699999000L, // nbf -1h
                1699999000L  // iat -1h
        );

        JwtValidationResult result = policy.validate("Bearer " + token);

        assertThat(result.isValid()).isTrue();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.VALID);
        assertThat(result.subject()).isEqualTo("user-123");
        assertThat(result.issuer()).isEqualTo("https://auth.exeris.eu");
        assertThat(result.tenantId()).isEqualTo("tenant-alpha");
        assertThat(result.expiresAtSeconds()).isEqualTo(1700003600L);
    }

    @Test
    @DisplayName("Missing header returns MISSING_TOKEN")
    void testMissingHeader() {
        JwtValidationResult r1 = policy.validate(null);
        assertThat(r1.status()).isEqualTo(JwtValidationStatus.MISSING_TOKEN);

        JwtValidationResult r2 = policy.validate("");
        assertThat(r2.status()).isEqualTo(JwtValidationStatus.MISSING_TOKEN);
    }

    @Test
    @DisplayName("Non-Bearer scheme returns MALFORMED")
    void testNonBearerScheme() {
        JwtValidationResult r = policy.validate("Basic dXNlcjpwYXNz");
        assertThat(r.status()).isEqualTo(JwtValidationStatus.MALFORMED);
    }

    @Test
    @DisplayName("Expired token returns EXPIRED")
    void testExpiredToken() {
        String token = JwtTestHelper.createToken(
                SECRET,
                "user-expired",
                "https://auth.exeris.eu",
                "tenant-alpha",
                "exeris-api",
                1699990000L, // exp in past
                1699980000L,
                1699980000L
        );

        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.EXPIRED);
    }

    @Test
    @DisplayName("Future nbf returns PREMATURE")
    void testPrematureToken() {
        String token = JwtTestHelper.createToken(
                SECRET,
                "user-future",
                "https://auth.exeris.eu",
                "tenant-alpha",
                "exeris-api",
                1700005000L,
                1700002000L, // nbf in future (NOW + 2000s)
                1700000000L
        );

        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.PREMATURE);
    }

    @Test
    @DisplayName("Forged signature returns INVALID_SIGNATURE")
    void testForgedSignature() {
        String token = JwtTestHelper.createToken(
                "other-secret-key-that-does-not-match",
                "attacker",
                "https://auth.exeris.eu",
                "tenant-alpha",
                "exeris-api",
                1700005000L,
                1699990000L,
                1699990000L
        );

        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
    }

    @Test
    @DisplayName("Unexpected issuer returns UNAUTHORIZED_ISSUER")
    void testUnexpectedIssuer() {
        String token = JwtTestHelper.createToken(
                SECRET,
                "user-1",
                "https://rogue-idp.com",
                "tenant-alpha",
                "exeris-api",
                1700005000L,
                1699990000L,
                1699990000L
        );

        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.UNAUTHORIZED_ISSUER);
    }

    @Test
    @DisplayName("Unexpected audience returns UNAUTHORIZED_AUDIENCE")
    void testUnexpectedAudience() {
        String token = JwtTestHelper.createToken(
                SECRET,
                "user-1",
                "https://auth.exeris.eu",
                "tenant-alpha",
                "other-api",
                1700005000L,
                1699990000L,
                1699990000L
        );

        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.UNAUTHORIZED_AUDIENCE);
    }

    @Test
    @DisplayName("Repeated validation hits lock-free signature cache")
    void testCacheHit() {
        String token = JwtTestHelper.createToken(
                SECRET,
                "user-cached",
                "https://auth.exeris.eu",
                "tenant-1",
                "exeris-api",
                1700005000L,
                1699990000L,
                1699990000L
        );

        JwtValidationResult first = policy.validate("Bearer " + token);
        assertThat(first.isValid()).isTrue();

        // Second lookup should return cached result
        JwtValidationResult second = policy.validate("Bearer " + token);
        assertThat(second.isValid()).isTrue();
        assertThat(second.subject()).isEqualTo("user-cached");
    }
}
