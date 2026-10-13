package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtValidationResult;
import eu.exeris.caps.jwt.api.JwtValidationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RS256 & ES256 (IEEE P1363) JWT Admission Policy Tests")
class Rs256AndEs256JwtAdmissionPolicyTest {

    private static final Instant NOW = Instant.ofEpochSecond(1700000000L);
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneId.of("UTC"));

    @Test
    @DisplayName("Valid RS256 token validated against RSA public key succeeds")
    void validRs256Token_succeeds() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        String kid = "rsa-key-1";

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .publicKey(kp.getPublic())
                .pinnedAlgorithm("RS256")
                .expectedIssuer("https://auth.exeris.eu")
                .expectedAudience("exeris-api")
                .leeway(Duration.ofSeconds(10))
                .clock(FIXED_CLOCK)
                .build();

        String token = createSignedToken(kp, "SHA256withRSA", kid, "RS256", "user-rsa", "https://auth.exeris.eu", "exeris-api", NOW.getEpochSecond() + 3600);

        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isTrue();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.VALID);
        assertThat(result.subject()).isEqualTo("user-rsa");
    }

    @Test
    @DisplayName("Forged RS256 token signed by rogue key fails")
    void forgedRs256Token_fails() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair legitKp = kpg.generateKeyPair();
        KeyPair rogueKp = kpg.generateKeyPair();

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.forRs256(legitKp.getPublic());
        String forgedToken = createSignedToken(rogueKp, "SHA256withRSA", "rsa-1", "RS256", "attacker", null, null, Instant.now().getEpochSecond() + 3600);

        JwtValidationResult result = policy.validate("Bearer " + forgedToken);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("RS256 signature verification failed");
    }

    @Test
    @DisplayName("RS256 token validated via JWKS containing RSA key succeeds")
    void rs256ViaJwks_succeeds() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RSAPublicKey rsaPub = (RSAPublicKey) kp.getPublic();

        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String nB64 = enc.encodeToString(stripLeadingZero(rsaPub.getModulus().toByteArray()));
        String eB64 = enc.encodeToString(stripLeadingZero(rsaPub.getPublicExponent().toByteArray()));

        String jwksJson = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"rsa-jwks-1\",\"n\":\""
                + nB64 + "\",\"e\":\"" + eB64 + "\"}]}";

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .jwks(jwksJson)
                .pinnedAlgorithm("RS256")
                .clock(FIXED_CLOCK)
                .build();

        String token = createSignedToken(kp, "SHA256withRSA", "rsa-jwks-1", "RS256", "alice", null, null, NOW.getEpochSecond() + 3600);
        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isTrue();
        assertThat(result.subject()).isEqualTo("alice");
    }

    @Test
    @DisplayName("Valid ES256 (IEEE P1363) token validated against EC public key succeeds")
    void validEs256Token_succeeds() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        String kid = "ec-key-1";

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .publicKey(kp.getPublic())
                .pinnedAlgorithm("ES256")
                .expectedIssuer("https://auth.exeris.eu")
                .expectedAudience("exeris-api")
                .clock(FIXED_CLOCK)
                .build();

        String token = createSignedToken(kp, "SHA256withECDSAinP1363Format", kid, "ES256", "user-ec", "https://auth.exeris.eu", "exeris-api", NOW.getEpochSecond() + 3600);

        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isTrue();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.VALID);
        assertThat(result.subject()).isEqualTo("user-ec");
    }

    @Test
    @DisplayName("Forged ES256 token signed by rogue key fails")
    void forgedEs256Token_fails() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair legitKp = kpg.generateKeyPair();
        KeyPair rogueKp = kpg.generateKeyPair();

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.forEs256(legitKp.getPublic());
        String forgedToken = createSignedToken(rogueKp, "SHA256withECDSAinP1363Format", "ec-1", "ES256", "attacker", null, null, Instant.now().getEpochSecond() + 3600);

        JwtValidationResult result = policy.validate("Bearer " + forgedToken);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("ES256 signature verification failed");
    }

    @Test
    @DisplayName("ES256 token validated via JWKS containing EC P-256 key succeeds")
    void es256ViaJwks_succeeds() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        ECPublicKey ecPub = (ECPublicKey) kp.getPublic();

        byte[] xBytes = to32Bytes(ecPub.getW().getAffineX().toByteArray());
        byte[] yBytes = to32Bytes(ecPub.getW().getAffineY().toByteArray());
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();

        String jwksJson = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"use\":\"sig\",\"kid\":\"ec-jwks-1\",\"x\":\""
                + enc.encodeToString(xBytes) + "\",\"y\":\"" + enc.encodeToString(yBytes) + "\"}]}";

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .jwks(jwksJson)
                .pinnedAlgorithm("ES256")
                .clock(FIXED_CLOCK)
                .build();

        String token = createSignedToken(kp, "SHA256withECDSAinP1363Format", "ec-jwks-1", "ES256", "bob", null, null, NOW.getEpochSecond() + 3600);
        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isTrue();
        assertThat(result.subject()).isEqualTo("bob");
    }

    @Test
    @DisplayName("Algorithm pinning rejects RS256 token when ES256 is pinned")
    void algorithmPinning_rejectsMismatch() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .publicKey(kp.getPublic())
                .pinnedAlgorithm("ES256")
                .clock(FIXED_CLOCK)
                .build();

        String token = createSignedToken(kp, "SHA256withRSA", "rsa-1", "RS256", "user", null, null, NOW.getEpochSecond() + 3600);
        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("Algorithm mismatch");
    }

    @Test
    @DisplayName("RS256 token missing kid against JWKS policy is rejected")
    void rs256MissingKid_fails() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RSAPublicKey rsaPub = (RSAPublicKey) kp.getPublic();

        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String nB64 = enc.encodeToString(stripLeadingZero(rsaPub.getModulus().toByteArray()));
        String eB64 = enc.encodeToString(stripLeadingZero(rsaPub.getPublicExponent().toByteArray()));

        String jwksJson = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"rsa-jwks-1\",\"n\":\""
                + nB64 + "\",\"e\":\"" + eB64 + "\"}]}";

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .jwks(jwksJson)
                .pinnedAlgorithm("RS256")
                .clock(FIXED_CLOCK)
                .build();

        String token = createSignedToken(kp, "SHA256withRSA", null, "RS256", "alice", null, null, NOW.getEpochSecond() + 3600);
        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("kid header missing");
    }

    @Test
    @DisplayName("ES256 token missing kid against JWKS policy is rejected")
    void es256MissingKid_fails() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        ECPublicKey ecPub = (ECPublicKey) kp.getPublic();

        byte[] xBytes = to32Bytes(ecPub.getW().getAffineX().toByteArray());
        byte[] yBytes = to32Bytes(ecPub.getW().getAffineY().toByteArray());
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();

        String jwksJson = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"use\":\"sig\",\"kid\":\"ec-jwks-1\",\"x\":\""
                + enc.encodeToString(xBytes) + "\",\"y\":\"" + enc.encodeToString(yBytes) + "\"}]}";

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .jwks(jwksJson)
                .pinnedAlgorithm("ES256")
                .clock(FIXED_CLOCK)
                .build();

        String token = createSignedToken(kp, "SHA256withECDSAinP1363Format", null, "ES256", "bob", null, null, NOW.getEpochSecond() + 3600);
        JwtValidationResult result = policy.validate("Bearer " + token);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("kid header missing");
    }

    @Test
    @DisplayName("RS256 signature with wrong byte length is cleanly rejected")
    void rs256SignatureLengthMismatch_fails() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .publicKey(kp.getPublic())
                .pinnedAlgorithm("RS256")
                .clock(FIXED_CLOCK)
                .build();
        String token = createSignedToken(kp, "SHA256withRSA", "rsa-1", "RS256", "alice", null, null, NOW.getEpochSecond() + 3600);
        // Truncate signature
        String truncatedToken = token.substring(0, token.lastIndexOf('.') + 1) + "AAAA";

        JwtValidationResult result = policy.validate("Bearer " + truncatedToken);
        assertThat(result.isValid()).isFalse();
        assertThat(result.status()).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        assertThat(result.errorMessage()).contains("RS256 signature length mismatch");
    }

    private String createSignedToken(KeyPair kp, String jcaAlgorithm, String keyId, String alg, String sub, String iss, String aud, long exp) throws Exception {
        String headerJson = "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"" + (keyId != null ? ",\"kid\":\"" + keyId + "\"" : "") + "}";
        String payloadJson = "{\"sub\":\"" + sub + "\""
                + (iss != null ? ",\"iss\":\"" + iss + "\"" : "")
                + (aud != null ? ",\"aud\":\"" + aud + "\"" : "")
                + ",\"exp\":" + exp + ",\"iat\":" + (NOW.getEpochSecond() - 60) + "}";

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String headerB64 = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64 + "." + payloadB64;

        Signature sig = Signature.getInstance(jcaAlgorithm);
        sig.initSign(kp.getPrivate());
        sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] signature = sig.sign();
        String sigB64 = encoder.encodeToString(signature);

        return signingInput + "." + sigB64;
    }

    private static byte[] stripLeadingZero(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] res = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, res, 0, res.length);
            return res;
        }
        return bytes;
    }

    private static byte[] to32Bytes(byte[] bytes) {
        byte[] stripped = stripLeadingZero(bytes);
        if (stripped.length == 32) {
            return stripped;
        }
        byte[] res = new byte[32];
        if (stripped.length < 32) {
            System.arraycopy(stripped, 0, res, 32 - stripped.length, stripped.length);
        } else {
            System.arraycopy(stripped, stripped.length - 32, res, 0, 32);
        }
        return res;
    }
}
