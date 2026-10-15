package eu.exeris.caps.jwt.internal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Per-request parsing")
class PerRequestParsingTest {

    private static final Pattern TREE_PARSER = Pattern.compile("internal/Json(?![A-Za-z0-9_$])");

    private static boolean referencesTreeParser(Class<?> type) throws IOException {
        try (InputStream in = type.getResourceAsStream(type.getSimpleName() + ".class")) {
            return TREE_PARSER.matcher(new String(in.readAllBytes(), StandardCharsets.ISO_8859_1)).find();
        }
    }

    @Test
    @DisplayName("the tree parser is used for the JWKS document and nowhere on the per-request path")
    void treeParserIsOffTheRequestPath() throws IOException {
        assertThat(referencesTreeParser(JwksKeySet.class)).as("detector finds the JWKS use").isTrue();
        for (Class<?> type : List.of(DefaultJwtAdmissionPolicy.class, JsonScanner.class, JwsHeaderScanner.class,
                JwtClaimsScanner.class, JwtAdmissionFilter.class)) {
            assertThat(referencesTreeParser(type)).as(type.getSimpleName()).isFalse();
        }
    }

    private static byte[] bytes(String json) {
        return json.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void headerReadsAlgKidAndCrit() {
        JwsHeaderScanner.Header header = JwsHeaderScanner.scan(bytes(
                "{\"typ\":\"JWT\",\"x\":{\"alg\":\"none\",\"a\":[1,{\"b\":null}]},\"alg\":\"EdDSA\",\"kid\":\"k1\"}"));
        assertThat(header.alg()).isEqualTo("EdDSA");
        assertThat(header.kid()).isEqualTo("k1");
        assertThat(header.critical()).isFalse();
        assertThat(JwsHeaderScanner.scan(bytes("{\"alg\":1,\"crit\":[]}"))).isEqualTo(
                new JwsHeaderScanner.Header(null, null, true));
    }

    @Test
    void headerReadsAnEscapedMemberName() {
        assertThat(JwsHeaderScanner.scan(bytes("{\"\\u0061lg\":\"EdDSA\"}")).alg()).isEqualTo("EdDSA");
    }

    @Test
    void repeatedReadMembersAreRefused() {
        assertThatThrownBy(() -> JwsHeaderScanner.scan(bytes("{\"alg\":\"EdDSA\",\"alg\":\"none\"}")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> JwsHeaderScanner.scan(bytes("{\"alg\":\"EdDSA\",\"\\u0061lg\":\"none\"}")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> JwtClaimsScanner.scan(bytes("{\"exp\":1,\"exp\":2}"), "aud", "tid"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void malformedDocumentsAreRefused() {
        for (String json : List.of("", "[]", "{", "{\"a\":}", "{\"a\":1,}", "{\"a\":01}", "{\"a\":\"\\q\"}",
                "{\"a\":1} x", "{\"a\":tru}", "{\"a\":\"\u0001\"}", "{\"a\":1.}", "{'a':1}")) {
            assertThatThrownBy(() -> JwsHeaderScanner.scan(bytes(json))).as(json)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void nestingIsBounded() {
        String ok = "{\"a\":" + "[".repeat(30) + "]".repeat(30) + "}";
        String tooDeep = "{\"a\":" + "[".repeat(40) + "]".repeat(40) + "}";
        JwsHeaderScanner.scan(bytes(ok));
        assertThatThrownBy(() -> JwsHeaderScanner.scan(bytes(tooDeep))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void integersAreExactAndOverflowIsNotAnInteger() {
        JwtClaimsScanner.Claims max = JwtClaimsScanner.scan(
                bytes("{\"exp\":9223372036854775807,\"nbf\":-9223372036854775808,\"iat\":9223372036854775808}"),
                "aud", "tid");
        assertThat(max.hasExp).isTrue();
        assertThat(max.exp).isEqualTo(Long.MAX_VALUE);
        assertThat(max.hasNbf).isTrue();
        assertThat(max.nbf).isEqualTo(Long.MIN_VALUE);
        assertThat(max.hasIat).isFalse();
        assertThat(max.iatWrong).isTrue();
        JwtClaimsScanner.Claims fractional = JwtClaimsScanner.scan(bytes("{\"exp\":1.5,\"nbf\":1e3}"), "aud", "tid");
        assertThat(fractional.hasExp).isFalse();
        assertThat(fractional.hasNbf).isFalse();
    }

    @Test
    void claimsReadAudienceTenantAndLists() {
        JwtClaimsScanner.Claims claims = JwtClaimsScanner.scan(bytes(
                "{\"iss\":\"i\",\"aud\":[\"x\",7,\"a\"],\"sub\":\"s\",\"tid\":\"t\",\"roles\":[\"r1\",\"r2\"],"
                        + "\"scope\":\"p q\",\"other\":{\"exp\":1}}"), "a", "tid");
        assertThat(claims.issuer).isEqualTo("i");
        assertThat(claims.audienceMatches).isTrue();
        assertThat(claims.subject).isEqualTo("s");
        assertThat(claims.tenant).isEqualTo("t");
        assertThat(claims.roles).containsExactly("r1", "r2");
        assertThat(claims.scopeString).isEqualTo("p q");
        assertThat(claims.hasExp).isFalse();
    }
}
