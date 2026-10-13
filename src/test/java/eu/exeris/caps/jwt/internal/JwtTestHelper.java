package eu.exeris.caps.jwt.internal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class JwtTestHelper {

    private JwtTestHelper() {
    }

    public static String createToken(
            String secret,
            String subject,
            String issuer,
            String tenantId,
            String audience,
            long expSeconds,
            long nbfSeconds,
            long iatSeconds
    ) {
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        StringBuilder payload = new StringBuilder("{");
        boolean first = true;
        if (subject != null) {
            payload.append("\"sub\":\"").append(subject).append("\"");
            first = false;
        }
        if (issuer != null) {
            if (!first) payload.append(",");
            payload.append("\"iss\":\"").append(issuer).append("\"");
            first = false;
        }
        if (tenantId != null) {
            if (!first) payload.append(",");
            payload.append("\"tid\":\"").append(tenantId).append("\"");
            first = false;
        }
        if (audience != null) {
            if (!first) payload.append(",");
            payload.append("\"aud\":\"").append(audience).append("\"");
            first = false;
        }
        if (expSeconds > 0) {
            if (!first) payload.append(",");
            payload.append("\"exp\":").append(expSeconds);
            first = false;
        }
        if (nbfSeconds > 0) {
            if (!first) payload.append(",");
            payload.append("\"nbf\":").append(nbfSeconds);
            first = false;
        }
        if (iatSeconds > 0) {
            if (!first) payload.append(",");
            payload.append("\"iat\":").append(iatSeconds);
        }
        payload.append("}");

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String headerB64 = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = encoder.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));

        String signingInput = headerB64 + "." + payloadB64;
        HmacSha256Validator validator = new HmacSha256Validator(secret.getBytes(StandardCharsets.UTF_8));
        byte[] sigBytes = validator.sign(signingInput, 0, signingInput.length());
        String sigB64 = encoder.encodeToString(sigBytes);

        return signingInput + "." + sigB64;
    }
}
