package eu.exeris.caps.jwt;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtServiceBoundaryBinding;
import eu.exeris.caps.jwt.internal.KernelAllocators;
import eu.exeris.caps.jwt.internal.RecordingExchange;
import eu.exeris.caps.jwt.internal.TestTokens;
import eu.exeris.caps.jwt.internal.TrackingAllocator;
import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("the admission filter's refusals send the exact headers, shared per kind of refusal")
class JwtRefusalHeadersTest {

    private static final KeyPair ED = TestTokens.ed25519();
    private static final HttpHeader CONTENT_TYPE = new HttpHeader("Content-Type", "application/problem+json");
    private static final HttpHeader NO_STORE = new HttpHeader("Cache-Control", "no-store");

    private static MemoryAllocator base;

    private ApiSurfaceRegistry registry;

    @BeforeAll
    static void openAllocator() {
        base = KernelAllocators.create();
    }

    @AfterAll
    static void closeAllocator() {
        base.close();
    }

    @BeforeEach
    void setUp() {
        ServiceBoundaryCoreModule sbc = new ServiceBoundaryCoreModule();
        registry = sbc.apiSurfaceRegistry();
        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .jwks(TestTokens.jwks(TestTokens.okpJwk("ed-1", ED)))
                .expectedIssuer(TestTokens.ISSUER)
                .expectedAudience(TestTokens.AUDIENCE)
                .clock(Clock.fixed(Instant.ofEpochSecond(TestTokens.NOW), ZoneOffset.UTC))
                .build();
        new JwtValidationModule(JwtServiceBoundaryBinding.of(sbc.requestFilterChain(), policy, Set.of()))
                .initialize();
        registry.registerRoute(ApiSurfaceRoute.builder()
                .method(HttpMethod.GET)
                .pathPattern("/me")
                .actionName("GET /me")
                .handler(ex -> ex.respond(HttpStatus.OK))
                .build());
    }

    private RecordingExchange send(String... authorization) {
        List<HttpHeader> headers = Arrays.stream(authorization).map(v -> new HttpHeader("Authorization", v)).toList();
        RecordingExchange exchange = new RecordingExchange(HttpMethod.GET, "/me", headers);
        KernelAllocators.bound(new TrackingAllocator(base), () -> registry.handle(exchange));
        return exchange;
    }

    @Test
    @DisplayName("a missing token: Content-Type, Cache-Control, WWW-Authenticate: Bearer")
    void missingToken() {
        RecordingExchange exchange = send();

        assertThat(exchange.status).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.response.headers()).containsExactly(CONTENT_TYPE, NO_STORE,
                new HttpHeader("WWW-Authenticate", "Bearer"));
    }

    @Test
    @DisplayName("a bad token and two tokens: Content-Type, Cache-Control, WWW-Authenticate with invalid_token")
    void invalidTokenKinds() {
        String token = "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), TestTokens.validClaims());
        HttpHeader challenge = new HttpHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");

        assertThat(send("Bearer not.a.token").response.headers()).containsExactly(CONTENT_TYPE, NO_STORE, challenge);
        assertThat(send(token, token).response.headers()).containsExactly(CONTENT_TYPE, NO_STORE, challenge);
    }

    @Test
    @DisplayName("refusals of the same kind hand the engine the same immutable list instance")
    void sameInstancePerKind() {
        List<HttpHeader> missing1 = send().response.headers();
        List<HttpHeader> missing2 = send().response.headers();
        List<HttpHeader> bad1 = send("Bearer not.a.token").response.headers();
        List<HttpHeader> bad2 = send("Bearer also.not.valid").response.headers();
        String token = "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), TestTokens.validClaims());
        List<HttpHeader> two = send(token, token).response.headers();

        assertThat(missing1).isSameAs(missing2);
        assertThat(bad1).isSameAs(bad2).isSameAs(two);
        assertThat(missing1).isNotSameAs(bad1);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> missing1.add(NO_STORE))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
