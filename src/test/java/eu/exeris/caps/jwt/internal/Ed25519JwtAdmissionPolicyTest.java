package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtValidationResult;
import eu.exeris.caps.jwt.api.JwtValidationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Ed25519 (EdDSA) JWT Admission Policy Tests (ADR-099 Zobowiązanie 8)")
class Ed25519JwtAdmissionPolicyTest {

    private static final Instant NOW = Instant.ofEpochSecond(1700000000L);
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneId.of("UTC"));

    private KeyPair keyPair;
    private String kid;
    private String jwksJson;
    private JwtAdmissionPolicy policy;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        keyPair = kpg.generateKeyPair();
        kid = "test-ed25519-key-1";

        byte[] pubEncoded = keyPair.getPublic().getEncoded();
        byte[] raw32 = new byte[32];
        System.arraycopy(pubEncoded, pubEncoded.length - 32, raw32, 0, 32);
        String xB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(raw32);

        jwksJson = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\",\"use\":\"sig\",\"kid\":\""
                + kid + "\",\"x\":\"" + xB64 + "\"}]}";

        policy = JwtAdmissionPolicies.builder()
                .jwks(jwksJson)
                .pinnedAlgorithm("EdDSA")
                .expectedIssuer("https://auth.exeris.eu")
                .expectedAudience("exeris-api")
                .leeway(Duration.ofSeconds(10))
                .clock(FIXED_CLOCK)
                .build();
    }

    private String createEd25519Token(KeyPair kp, String keyId, String alg, String sub, String iss, String aud, long exp) throws Exception {
        String headerJson = "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"" + (keyId != null ? ",\"kid\":\"" + keyId + "\"" : "") + "}";
        String payloadJson = "{\"sub\":\"" + sub + "\",\"iss\":\"" + iss + "\",\"aud\":\"" + aud + "\",\"exp\":" + exp + ",\"iat\":" + (NOW.getEpochSecond() - 60) + "}";

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String headerB64 = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64 + "." + payloadB64;

        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(kp.getPrivate());
        sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] signature = sig.sign();
        String sigB64 = encoder.encodeToString(signature);

        return signingInput + "." + sigB64;
    }

    @Test
    @DisplayName("Valid Ed25519 token validated against JWKS succeeds")
    void validEd25519Token() throws Exception {
        String token = createEd25519Token(keyPair, kid, "EdDSA", "user-ed", "https://auth.exeris.eu", "exeris-api", NOW.getEpochSecond() + 3600);

        JwtValidationResult result = policy.validate("Bearer " + token);

        assertThat(result.isValid()).isTrue();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.VALID);
        assertThat(result.subject()).isEqualTo("user-ed");
        assertThat(result.issuer()).isEqualTo("https://auth.exeris.eu");
    }

    @Test
    @DisplayName("Algorithm pinning rejects HS256 token when EdDSA is expected")
    void algorithmPinningRejectsMismatch() throws Exception {
        String token = JwtTestHelper.createToken(
                "secret-key-32-bytes-long-for-test!!",
                "attacker",
                "https://auth.exeris.eu",
                "tenant-1",
                "exeris-api",
                NOW.getEpochSecond() + 3600,
                NOW.getEpochSecond() - 60,
                NOW.getEpochSecond() - 60
        );

        JwtValidationResult result = policy.validate("Bearer " + token);

        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("Algorithm mismatch");
    }

    @Test
    @DisplayName("Forged signature with different Ed25519 key fails")
    void forgedSignatureFails() throws Exception {
        KeyPair otherKp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String token = createEd25519Token(otherKp, kid, "EdDSA", "user-fake", "https://auth.exeris.eu", "exeris-api", NOW.getEpochSecond() + 3600);

        JwtValidationResult result = policy.validate("Bearer " + token);

        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
    }

    @Test
    @DisplayName("Unknown key id fails validation")
    void unknownKidFails() throws Exception {
        String token = createEd25519Token(keyPair, "unknown-kid", "EdDSA", "user-ed", "https://auth.exeris.eu", "exeris-api", NOW.getEpochSecond() + 3600);

        JwtValidationResult result = policy.validate("Bearer " + token);

        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("Unknown or unresolvable key id");
    }

    @Test
    @DisplayName("Missing key id fails validation on asymmetric token")
    void missingKidFails() throws Exception {
        String token = createEd25519Token(keyPair, null, "EdDSA", "user-ed", "https://auth.exeris.eu", "exeris-api", NOW.getEpochSecond() + 3600);

        JwtValidationResult result = policy.validate("Bearer " + token);

        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("kid header missing");
    }
}
