package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtValidationResult;
import eu.exeris.caps.jwt.api.JwtValidationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static eu.exeris.caps.jwt.internal.TestTokens.AUDIENCE;
import static eu.exeris.caps.jwt.internal.TestTokens.ISSUER;
import static eu.exeris.caps.jwt.internal.TestTokens.NOW;
import static eu.exeris.caps.jwt.internal.TestTokens.SUBJECT;
import static eu.exeris.caps.jwt.internal.TestTokens.validClaims;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultJwtAdmissionPolicy")
class DefaultJwtAdmissionPolicyTest {

    private static final KeyPair ED = TestTokens.ed25519();
    private static final KeyPair RSA = TestTokens.rsa(2048);
    private static final String JWKS = TestTokens.jwks(TestTokens.okpJwk("ed-1", ED), TestTokens.rsaJwk("rsa-1", RSA));

    private static JwtAdmissionPolicies.Builder base() {
        return JwtAdmissionPolicies.builder()
                .jwks(JWKS)
                .expectedIssuer(ISSUER)
                .expectedAudience(AUDIENCE)
                .clockSkew(Duration.ofSeconds(30))
                .clock(Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC));
    }

    private static final JwtAdmissionPolicy POLICY = base().build();

    private static JwtValidationStatus status(String token) {
        return POLICY.validateToken(token).status();
    }

    private static String claims(String json) {
        return json.replace("ISS", ISSUER).replace("AUD", AUDIENCE).replace("SUB", SUBJECT);
    }

    @Test
    @DisplayName("accepts an EdDSA token and returns its subject, tenant, session, roles and scopes")
    void acceptsValidEdDsa() {
        JwtValidationResult result = POLICY.validate("Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), validClaims()));

        assertThat(result.status()).isEqualTo(JwtValidationStatus.VALID);
        assertThat(result.subject()).isEqualTo(SUBJECT);
        assertThat(result.issuer()).isEqualTo(ISSUER);
        assertThat(result.tenantId()).isEqualTo(TestTokens.TENANT);
        assertThat(result.sessionId()).isEqualTo(TestTokens.SESSION);
        assertThat(result.roles()).containsExactlyInAnyOrder("owner", "admin");
        assertThat(result.scopes()).containsExactlyInAnyOrder("tenants:read", "tenants:write");
        assertThat(result.expiresAtSeconds()).isEqualTo(NOW + 300);
    }

    @Nested
    @DisplayName("parse")
    class Parse {

        @Test
        void missingToken() {
            assertThat(POLICY.validate(null).status()).isEqualTo(JwtValidationStatus.MISSING_TOKEN);
            assertThat(POLICY.validate("").status()).isEqualTo(JwtValidationStatus.MISSING_TOKEN);
        }

        @Test
        void notBearer() {
            assertThat(POLICY.validate("Basic dXNlcjpwYXNz").status()).isEqualTo(JwtValidationStatus.MALFORMED);
        }

        @Test
        void wrongSegmentCount() {
            assertThat(status("aaa.bbb")).isEqualTo(JwtValidationStatus.MALFORMED);
            assertThat(status("aaa.bbb.ccc.ddd")).isEqualTo(JwtValidationStatus.MALFORMED);
            assertThat(status("aaa..ccc")).isEqualTo(JwtValidationStatus.MALFORMED);
        }

        @Test
        void foreignCharacters() {
            assertThat(status("a+a.b/b.c=c")).isEqualTo(JwtValidationStatus.MALFORMED);
        }

        @Test
        void headerNotJson() {
            assertThat(status(TestTokens.encode("not json") + "." + TestTokens.encode("{}") + ".AAAA"))
                    .isEqualTo(JwtValidationStatus.MALFORMED);
        }

        @Test
        void duplicateHeaderMember() {
            String token = TestTokens.sign("{\"alg\":\"EdDSA\",\"kid\":\"ed-1\",\"alg\":\"RS256\"}", validClaims(),
                    "Ed25519", ED.getPrivate());
            assertThat(status(token)).isEqualTo(JwtValidationStatus.MALFORMED);
        }

        @Test
        void missingAlg() {
            String token = TestTokens.sign("{\"kid\":\"ed-1\"}", validClaims(), "Ed25519", ED.getPrivate());
            assertThat(status(token)).isEqualTo(JwtValidationStatus.MALFORMED);
        }

        @Test
        void criticalHeader() {
            String token = TestTokens.sign("{\"alg\":\"EdDSA\",\"kid\":\"ed-1\",\"crit\":[\"exp\"]}", validClaims(),
                    "Ed25519", ED.getPrivate());
            assertThat(status(token)).isEqualTo(JwtValidationStatus.MALFORMED);
        }

        @Test
        void tooLong() {
            assertThat(status("a".repeat(DefaultJwtAdmissionPolicy.MAX_TOKEN_LENGTH + 1)))
                    .isEqualTo(JwtValidationStatus.MALFORMED);
        }
    }

    @Nested
    @DisplayName("kid and key")
    class KidAndKey {

        @Test
        void missingKid() {
            String token = TestTokens.sign("{\"alg\":\"EdDSA\"}", validClaims(), "Ed25519", ED.getPrivate());
            assertThat(status(token)).isEqualTo(JwtValidationStatus.UNKNOWN_KEY);
        }

        @Test
        void unknownKid() {
            assertThat(status(TestTokens.eddsa("ed-unknown", ED.getPrivate(), validClaims())))
                    .isEqualTo(JwtValidationStatus.UNKNOWN_KEY);
        }
    }

    @Nested
    @DisplayName("algorithm pinned to the key before the signature")
    class AlgorithmConfusion {

        @Test
        @DisplayName("an EdDSA token presented under an RSA kid is refused")
        void eddsaUnderRsaKid() {
            String token = TestTokens.sign("{\"alg\":\"EdDSA\",\"kid\":\"rsa-1\"}", validClaims(), "Ed25519", ED.getPrivate());
            assertThat(base().acceptRs256().build().validateToken(token).status())
                    .isEqualTo(JwtValidationStatus.ALGORITHM_MISMATCH);
        }

        @Test
        @DisplayName("an RS256 token presented under an Ed25519 kid is refused")
        void rs256UnderEd25519Kid() {
            String token = TestTokens.sign("{\"alg\":\"RS256\",\"kid\":\"ed-1\"}", validClaims(), "SHA256withRSA", RSA.getPrivate());
            assertThat(base().acceptRs256().build().validateToken(token).status())
                    .isEqualTo(JwtValidationStatus.ALGORITHM_MISMATCH);
        }

        @Test
        @DisplayName("HS256 keyed with the RSA public key, under the RSA kid, is refused")
        void hmacWithPublicKeyAsSecret() throws Exception {
            String header = TestTokens.encode("{\"alg\":\"HS256\",\"kid\":\"rsa-1\"}");
            String payload = TestTokens.encode(validClaims());
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(RSA.getPublic().getEncoded(), "HmacSHA256"));
            byte[] sig = mac.doFinal((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
            String token = header + "." + payload + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
            assertThat(base().acceptRs256().build().validateToken(token).status())
                    .isEqualTo(JwtValidationStatus.ALGORITHM_MISMATCH);
        }

        @Test
        @DisplayName("alg none is refused")
        void algNone() {
            String token = TestTokens.unsigned("{\"alg\":\"none\",\"kid\":\"ed-1\"}", validClaims(), new byte[]{1});
            assertThat(status(token)).isEqualTo(JwtValidationStatus.ALGORITHM_MISMATCH);
        }

        @Test
        @DisplayName("RS256 is refused unless configured, even with a valid signature")
        void rs256NotAccepted() {
            String token = TestTokens.rs256("rsa-1", RSA.getPrivate(), validClaims());
            assertThat(status(token)).isEqualTo(JwtValidationStatus.ALGORITHM_MISMATCH);
            assertThat(base().acceptRs256().build().validateToken(token).status()).isEqualTo(JwtValidationStatus.VALID);
        }
    }

    @Nested
    @DisplayName("signature")
    class SignatureChecks {

        @Test
        void wrongKey() {
            KeyPair other = TestTokens.ed25519();
            assertThat(status(TestTokens.eddsa("ed-1", other.getPrivate(), validClaims())))
                    .isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        }

        @Test
        @DisplayName("a tampered payload fails even after the original token was accepted")
        void tamperedAfterAcceptance() {
            String token = TestTokens.eddsa("ed-1", ED.getPrivate(), validClaims());
            assertThat(status(token)).isEqualTo(JwtValidationStatus.VALID);

            String[] parts = token.split("\\.");
            String forged = parts[0] + "." + TestTokens.encode(validClaims().replace("owner", "root!")) + "." + parts[2];
            assertThat(status(forged)).isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        }

        @Test
        @DisplayName("claims are not read before the signature: an expired forgery reports the signature")
        void signatureBeforeClaims() {
            KeyPair other = TestTokens.ed25519();
            String expired = claims("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":1}");
            assertThat(status(TestTokens.eddsa("ed-1", other.getPrivate(), expired)))
                    .isEqualTo(JwtValidationStatus.INVALID_SIGNATURE);
        }
    }

    @Nested
    @DisplayName("claims")
    class Claims {

        private JwtValidationStatus signed(String json) {
            return status(TestTokens.eddsa("ed-1", ED.getPrivate(), claims(json)));
        }

        @Test
        void wrongIssuer() {
            assertThat(signed("{\"iss\":\"https://evil.test\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":" + (NOW + 60) + "}"))
                    .isEqualTo(JwtValidationStatus.UNAUTHORIZED_ISSUER);
        }

        @Test
        void wrongAudience() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"other\",\"sub\":\"SUB\",\"exp\":" + (NOW + 60) + "}"))
                    .isEqualTo(JwtValidationStatus.UNAUTHORIZED_AUDIENCE);
            assertThat(signed("{\"iss\":\"ISS\",\"sub\":\"SUB\",\"exp\":" + (NOW + 60) + "}"))
                    .isEqualTo(JwtValidationStatus.UNAUTHORIZED_AUDIENCE);
        }

        @Test
        void audienceArray() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":[\"other\",\"AUD\"],\"sub\":\"SUB\",\"exp\":" + (NOW + 60) + "}"))
                    .isEqualTo(JwtValidationStatus.VALID);
        }

        @Test
        @DisplayName("a token without exp is refused")
        void missingExp() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\"}"))
                    .isEqualTo(JwtValidationStatus.MISSING_CLAIM);
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":\"" + (NOW + 60) + "\"}"))
                    .isEqualTo(JwtValidationStatus.MISSING_CLAIM);
        }

        @Test
        void expiredBeyondSkew() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":" + (NOW - 31) + "}"))
                    .isEqualTo(JwtValidationStatus.EXPIRED);
        }

        @Test
        void expiredWithinSkew() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":" + (NOW - 30) + "}"))
                    .isEqualTo(JwtValidationStatus.VALID);
        }

        @Test
        void notBeforeInFuture() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":" + (NOW + 600) + ",\"nbf\":" + (NOW + 31) + "}"))
                    .isEqualTo(JwtValidationStatus.PREMATURE);
        }

        @Test
        void issuedInFuture() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":" + (NOW + 600) + ",\"iat\":" + (NOW + 31) + "}"))
                    .isEqualTo(JwtValidationStatus.PREMATURE);
        }

        @Test
        void missingSubject() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"exp\":" + (NOW + 60) + "}"))
                    .isEqualTo(JwtValidationStatus.MISSING_CLAIM);
        }

        @Test
        void rolesOfWrongType() {
            assertThat(signed("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":" + (NOW + 60) + ",\"roles\":\"admin\"}"))
                    .isEqualTo(JwtValidationStatus.MALFORMED);
        }

        @Test
        @DisplayName("the tenant claim name is configurable")
        void configurableTenantClaim() {
            JwtAdmissionPolicy policy = base().tenantClaim("tid").build();
            String token = TestTokens.eddsa("ed-1", ED.getPrivate(),
                    claims("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":" + (NOW + 60) + ",\"tid\":\"t-1\",\"tenant_id\":\"t-2\"}"));
            assertThat(policy.validateToken(token).tenantId()).isEqualTo("t-1");
        }
    }

    @Nested
    @DisplayName("configuration")
    class Configuration {

        @Test
        void requiresIssuerAndAudience() {
            assertThatThrownBy(() -> JwtAdmissionPolicies.builder().jwks(JWKS).expectedAudience(AUDIENCE).build())
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> JwtAdmissionPolicies.builder().jwks(JWKS).expectedIssuer(ISSUER).build())
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void boundsClockSkew() {
            assertThatThrownBy(() -> base().clockSkew(Duration.ofMinutes(6)).build())
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void requiresExactlyOneKeySource() {
            assertThatThrownBy(() -> base().publicKey("k", ED.getPublic()).build())
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> JwtAdmissionPolicies.builder().expectedIssuer(ISSUER).expectedAudience(AUDIENCE).build())
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void refusesUnsupportedAlgorithms() {
            assertThatThrownBy(() -> base().acceptedAlgorithms(java.util.Set.of("HS256")).build())
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        void fixedPublicKey() {
            JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                    .publicKey("ed-1", ED.getPublic())
                    .expectedIssuer(ISSUER)
                    .expectedAudience(AUDIENCE)
                    .clock(Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC))
                    .build();
            assertThat(policy.validateToken(TestTokens.eddsa("ed-1", ED.getPrivate(), validClaims())).isValid()).isTrue();
        }

        @Test
        void fromProperties() {
            JwtAdmissionPolicy policy = JwtAdmissionPolicies.fromProperties(java.util.Map.of(
                    JwtAdmissionPolicies.KEY_ISSUER, ISSUER,
                    JwtAdmissionPolicies.KEY_AUDIENCE, AUDIENCE,
                    JwtAdmissionPolicies.KEY_ALGORITHMS, "EdDSA, RS256"), () -> JWKS);
            String rs = TestTokens.rs256("rsa-1", RSA.getPrivate(),
                    claims("{\"iss\":\"ISS\",\"aud\":\"AUD\",\"sub\":\"SUB\",\"exp\":" + (Instant.now().getEpochSecond() + 60) + "}"));
            assertThat(policy.validateToken(rs).status()).isEqualTo(JwtValidationStatus.VALID);
        }
    }
}
