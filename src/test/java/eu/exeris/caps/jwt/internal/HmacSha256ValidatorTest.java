package eu.exeris.caps.jwt.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("HmacSha256Validator Unit Tests")
class HmacSha256ValidatorTest {

    private static final String SECRET = "super-secret-key-for-jwt-validation-256-bit";

    @Test
    @DisplayName("Verifies valid HMAC-SHA256 signature correctly")
    void testValidSignature() {
        HmacSha256Validator validator = new HmacSha256Validator(SECRET.getBytes(StandardCharsets.UTF_8));
        String input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

        byte[] sig = validator.sign(input, 0, input.length());
        assertThat(sig).hasSize(32);

        boolean verified = validator.verify(input, 0, input.length(), sig);
        assertThat(verified).isTrue();
    }

    @Test
    @DisplayName("Rejects tampered input")
    void testTamperedInput() {
        HmacSha256Validator validator = new HmacSha256Validator(SECRET.getBytes(StandardCharsets.UTF_8));
        String input = "valid.payload";
        byte[] sig = validator.sign(input, 0, input.length());

        String tampered = "valid.payloae";
        boolean verified = validator.verify(tampered, 0, tampered.length(), sig);
        assertThat(verified).isFalse();
    }

    @Test
    @DisplayName("Rejects signature generated with wrong secret")
    void testWrongSecret() {
        HmacSha256Validator v1 = new HmacSha256Validator("secret-1".getBytes(StandardCharsets.UTF_8));
        HmacSha256Validator v2 = new HmacSha256Validator("secret-2".getBytes(StandardCharsets.UTF_8));

        String input = "header.payload";
        byte[] sig1 = v1.sign(input, 0, input.length());

        boolean verified = v2.verify(input, 0, input.length(), sig1);
        assertThat(verified).isFalse();
    }
}
