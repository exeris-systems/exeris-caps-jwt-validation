package eu.exeris.caps.jwt.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Base64UrlDecoder Unit Tests")
class Base64UrlDecoderTest {

    @Test
    @DisplayName("Roundtrip decodes against java.util.Base64")
    void testRoundtrip() {
        String[] testStrings = {
                "",
                "f",
                "fo",
                "foo",
                "foob",
                "fooba",
                "foobar",
                "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true,\"iat\":1516239022}"
        };

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

        for (String original : testStrings) {
            byte[] origBytes = original.getBytes(StandardCharsets.UTF_8);
            String encoded = encoder.encodeToString(origBytes);

            int decodedLen = Base64UrlDecoder.decodedLength(encoded, 0, encoded.length());
            assertThat(decodedLen).isEqualTo(origBytes.length);

            byte[] decoded = Base64UrlDecoder.decodeToBytes(encoded, 0, encoded.length());
            assertThat(decoded).isEqualTo(origBytes);
        }
    }

    @Test
    @DisplayName("Rejects invalid base64 characters")
    void testInvalidCharacters() {
        String invalid = "a!b@c#d$";
        byte[] decoded = Base64UrlDecoder.decodeToBytes(invalid, 0, invalid.length());
        assertThat(decoded).isNull();
    }

    @Test
    @DisplayName("Handles padded and unpadded Base64URL")
    void testPadding() {
        String unpadded = "YQ"; // "a"
        String padded = "YQ==";

        byte[] d1 = Base64UrlDecoder.decodeToBytes(unpadded, 0, unpadded.length());
        byte[] d2 = Base64UrlDecoder.decodeToBytes(padded, 0, padded.length());

        assertThat(d1).containsExactly((byte) 'a');
        assertThat(d2).containsExactly((byte) 'a');
    }
}
