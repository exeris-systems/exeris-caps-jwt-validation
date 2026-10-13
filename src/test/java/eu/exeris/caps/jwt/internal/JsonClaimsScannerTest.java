package eu.exeris.caps.jwt.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JsonClaimsScanner Unit Tests")
class JsonClaimsScannerTest {

    @Test
    @DisplayName("Extracts all standard JWT claims from compact JSON")
    void testStandardClaims() {
        String json = "{\"sub\":\"user-42\",\"iss\":\"https://auth.exeris.eu\",\"tid\":\"tenant-100\",\"aud\":\"gateway-api\",\"exp\":1893456000,\"nbf\":1577836800,\"iat\":1577836800}";
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

        JsonClaimsScanner.ParsedClaims claims = JsonClaimsScanner.scan(bytes);

        assertThat(claims).isNotNull();
        assertThat(claims.subject()).isEqualTo("user-42");
        assertThat(claims.issuer()).isEqualTo("https://auth.exeris.eu");
        assertThat(claims.tenantId()).isEqualTo("tenant-100");
        assertThat(claims.audience()).isEqualTo("gateway-api");
        assertThat(claims.expiresAt()).isEqualTo(1893456000L);
        assertThat(claims.notBefore()).isEqualTo(1577836800L);
        assertThat(claims.issuedAt()).isEqualTo(1577836800L);
    }

    @Test
    @DisplayName("Extracts tenant_id alternative claim")
    void testTenantIdAlternativeKey() {
        String json = "{\"sub\":\"alice\",\"tenant_id\":\"org-corp\"}";
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

        JsonClaimsScanner.ParsedClaims claims = JsonClaimsScanner.scan(bytes);

        assertThat(claims).isNotNull();
        assertThat(claims.subject()).isEqualTo("alice");
        assertThat(claims.tenantId()).isEqualTo("org-corp");
    }

    @Test
    @DisplayName("Extracts audience from JSON array")
    void testArrayAudience() {
        String json = "{\"sub\":\"bob\",\"aud\":[\"api.first\",\"api.second\"]}";
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

        JsonClaimsScanner.ParsedClaims claims = JsonClaimsScanner.scan(bytes);

        assertThat(claims).isNotNull();
        assertThat(claims.subject()).isEqualTo("bob");
        assertThat(claims.audience()).isEqualTo("api.first");
    }

    @Test
    @DisplayName("Handles whitespace and newlines formatted JSON")
    void testFormattedJson() {
        String json = """
                {
                  "sub": "carol",
                  "exp": 1999999999,
                  "iss": "exeris"
                }
                """;
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

        JsonClaimsScanner.ParsedClaims claims = JsonClaimsScanner.scan(bytes);

        assertThat(claims).isNotNull();
        assertThat(claims.subject()).isEqualTo("carol");
        assertThat(claims.expiresAt()).isEqualTo(1999999999L);
        assertThat(claims.issuer()).isEqualTo("exeris");
    }

    @Test
    @DisplayName("Returns null on malformed JSON")
    void testMalformedJson() {
        String invalid = "not a json";
        assertThat(JsonClaimsScanner.scan(invalid.getBytes(StandardCharsets.UTF_8))).isNull();

        String unclosed = "{\"sub\":\"incomplete";
        assertThat(JsonClaimsScanner.scan(unclosed.getBytes(StandardCharsets.UTF_8))).isNull();
    }
}
