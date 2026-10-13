package eu.exeris.caps.jwt;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtPrincipal;
import eu.exeris.caps.jwt.api.JwtServiceBoundaryBinding;
import eu.exeris.caps.jwt.internal.RecordingExchange;
import eu.exeris.caps.jwt.internal.TestTokens;
import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.serviceboundarycore.api.RequestContext;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("jwt-validation as a Service Boundary admission filter")
class JwtServiceBoundaryFilterTest {

    private static final KeyPair ED = TestTokens.ed25519();

    private ApiSurfaceRegistry registry;
    private JwtValidationModule module;
    private final AtomicReference<RequestContext> seen = new AtomicReference<>();

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
        Set<String> anonymous = JwtServiceBoundaryBinding.anonymousRoutes(
                Map.of(JwtServiceBoundaryBinding.KEY_ANONYMOUS_ROUTES, "POST /login, GET  /status"));
        module = new JwtValidationModule(JwtServiceBoundaryBinding.of(sbc.requestFilterChain(), policy, anonymous));
        module.initialize();
        for (String route : List.of("GET /me", "POST /login", "GET /status")) {
            String[] parts = route.split(" ");
            registry.registerRoute(ApiSurfaceRoute.builder()
                    .method(HttpMethod.valueOf(parts[0]))
                    .pathPattern(parts[1])
                    .actionName(route)
                    .handler(ex -> {
                        seen.set(RequestContext.current());
                        ex.respond(HttpStatus.OK);
                    })
                    .build());
        }
    }

    private RecordingExchange send(HttpMethod method, String path, String... authorization) {
        List<HttpHeader> headers = java.util.Arrays.stream(authorization).map(v -> new HttpHeader("Authorization", v)).toList();
        RecordingExchange exchange = new RecordingExchange(method, path, headers);
        registry.handle(exchange);
        return exchange;
    }

    @Test
    @DisplayName("a verified token's subject, tenant, session, roles and scopes reach the handler's RequestContext")
    void propagatesPrincipal() {
        RecordingExchange exchange = send(HttpMethod.GET, "/me",
                "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), TestTokens.validClaims()));

        assertThat(exchange.status).isEqualTo(HttpStatus.OK);
        RequestContext context = seen.get();
        assertThat(context.principal()).get().isInstanceOf(JwtPrincipal.class);
        JwtPrincipal principal = (JwtPrincipal) context.principal().orElseThrow();
        assertThat(principal.principalId()).isEqualTo(UUID.fromString(TestTokens.SUBJECT));
        assertThat(principal.tenantId()).contains(UUID.fromString(TestTokens.TENANT));
        assertThat(principal.sessionId()).contains(UUID.fromString(TestTokens.SESSION));
        assertThat(principal.roles()).containsExactlyInAnyOrder("owner", "admin");
        assertThat(principal.scopes()).containsExactlyInAnyOrder("tenants:read", "tenants:write");
        assertThat(context.tenantId()).isEqualTo(TestTokens.TENANT);
    }

    @Test
    @DisplayName("a missing token on a protected route is answered 401 with a problem body")
    void missingToken() {
        RecordingExchange exchange = send(HttpMethod.GET, "/me");

        assertThat(exchange.status).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.header("Content-Type")).contains("application/problem+json");
        assertThat(exchange.header("WWW-Authenticate")).contains("Bearer");
        assertThat(exchange.body()).isEqualTo("{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401,"
                + "\"detail\":\"The request lacks valid bearer credentials.\"}");
        assertThat(seen.get()).isNull();
    }

    @Test
    @DisplayName("an invalid token is answered 401 with the same fixed body, naming nothing about the token")
    void invalidToken() {
        KeyPair attacker = TestTokens.ed25519();
        RecordingExchange exchange = send(HttpMethod.GET, "/me",
                "Bearer " + TestTokens.eddsa("ed-1", attacker.getPrivate(), TestTokens.validClaims()));

        assertThat(exchange.status).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.header("WWW-Authenticate")).contains("Bearer error=\"invalid_token\"");
        assertThat(exchange.body()).doesNotContain("signature", "Exception", TestTokens.SUBJECT);
        assertThat(seen.get()).isNull();
    }

    @Test
    @DisplayName("an anonymous route admits a request without a token, with no principal")
    void anonymousRoute() {
        RecordingExchange exchange = send(HttpMethod.POST, "/login");

        assertThat(exchange.status).isEqualTo(HttpStatus.OK);
        assertThat(seen.get().principal()).isEmpty();
        assertThat(send(HttpMethod.GET, "/status").status).isEqualTo(HttpStatus.OK);
    }

    @Test
    @DisplayName("an anonymous route still refuses a bad token")
    void anonymousRouteBadToken() {
        assertThat(send(HttpMethod.POST, "/login", "Bearer not.a.token").status).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("two Authorization headers are refused")
    void twoAuthorizationHeaders() {
        String token = "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), TestTokens.validClaims());
        assertThat(send(HttpMethod.GET, "/me", token, token).status).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("a verified token whose sub is not a UUID is refused")
    void nonUuidSubject() {
        String claims = TestTokens.validClaims().replace(TestTokens.SUBJECT, "alice");
        assertThat(send(HttpMethod.GET, "/me", "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), claims)).status)
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("terminate removes the filter from the chain")
    void terminateDetaches() {
        assertThat(registry.filters()).hasSize(1);
        module.terminate();
        assertThat(registry.filters()).isEmpty();
    }

    @Test
    @DisplayName("with no admission host bound the module refuses to initialise")
    void refusesWithoutHost() {
        assertThatThrownBy(() -> new JwtValidationModule().initialize())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no admission host");
    }

    @Test
    void malformedAnonymousRouteConfig() {
        assertThatThrownBy(() -> JwtServiceBoundaryBinding.anonymousRoutes(
                Map.of(JwtServiceBoundaryBinding.KEY_ANONYMOUS_ROUTES, "/login")))
                .isInstanceOf(IllegalStateException.class);
    }
}
