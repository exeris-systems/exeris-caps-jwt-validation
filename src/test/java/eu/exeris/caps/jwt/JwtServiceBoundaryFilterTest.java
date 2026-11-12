package eu.exeris.caps.jwt;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtPrincipal;
import eu.exeris.caps.jwt.api.JwtServiceBoundaryBinding;
import eu.exeris.caps.jwt.internal.KernelAllocators;
import eu.exeris.caps.jwt.internal.RecordingExchange;
import eu.exeris.caps.jwt.internal.TrackingAllocator;
import eu.exeris.caps.jwt.internal.TestTokens;
import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.serviceboundarycore.api.RequestContext;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.http.RouteRequirement;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
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

    private static MemoryAllocator base;

    private TrackingAllocator allocator;
    private ApiSurfaceRegistry registry;
    private JwtValidationModule module;
    private final AtomicReference<RequestContext> seen = new AtomicReference<>();

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
        allocator = new TrackingAllocator(base);
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
                    .requirements(List.of("GET /me".equals(route)
                            ? RouteRequirement.authenticated() : RouteRequirement.permitAll()))
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
        KernelAllocators.bound(allocator, () -> registry.handle(exchange));
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
        assertThat(context.tenantId()).contains(TestTokens.TENANT);
        assertThat(context.sessionId()).contains(UUID.fromString(TestTokens.SESSION));
    }

    @Test
    @DisplayName("a verified token without a sid claim leaves the session id empty")
    void tokenWithoutSession() {
        String claims = TestTokens.validClaims().replace(",\"sid\":\"" + TestTokens.SESSION + "\"", "");
        RecordingExchange exchange = send(HttpMethod.GET, "/me",
                "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), claims));

        assertThat(exchange.status).isEqualTo(HttpStatus.OK);
        assertThat(seen.get().principal()).isPresent();
        assertThat(seen.get().tenantId()).contains(TestTokens.TENANT);
        assertThat(seen.get().sessionId()).isEmpty();
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
        assertThat(allocator.allocations()).isEqualTo(1);
        assertThat(allocator.finalReleases()).isEqualTo(1);
        assertThat(allocator.buffers().getFirst().closeCalls()).isEqualTo(1);
        assertThat(exchange.header("Content-Length")).isIn(java.util.Optional.empty(),
                java.util.Optional.of(String.valueOf(exchange.body().getBytes(java.nio.charset.StandardCharsets.UTF_8).length)));
    }

    @Test
    @DisplayName("a refusal over HTTP/2 keeps its buffer alive past the filter until the engine releases it")
    void refusalOverHttp2() {
        RecordingExchange exchange = new RecordingExchange(HttpMethod.GET, "/me", List.of(), HttpVersion.HTTP_2,
                RecordingExchange.Mode.RELEASE_DEFERRED);
        KernelAllocators.bound(allocator, () -> registry.handle(exchange));

        assertThat(exchange.status).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.response.version()).isEqualTo(HttpVersion.HTTP_2);
        assertThat(allocator.buffers().getFirst().isAlive()).isTrue();
        assertThat(allocator.buffers().getFirst().closeCalls()).isZero();
        exchange.completeDeferred();
        assertThat(allocator.outstanding()).isZero();
        assertThat(exchange.body()).startsWith("{\"type\":\"about:blank\"");
    }

    @Test
    @DisplayName("every refusal path (no token, bad token, two tokens) releases its buffer exactly once")
    void everyRefusalReleasesOnce() {
        String token = "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), TestTokens.validClaims());
        send(HttpMethod.GET, "/me");
        send(HttpMethod.GET, "/me", "Bearer not.a.token");
        send(HttpMethod.GET, "/me", token, token);

        assertThat(allocator.allocations()).isEqualTo(3);
        assertThat(allocator.finalReleases()).isEqualTo(3);
        assertThat(allocator.buffers()).allSatisfy(b -> assertThat(b.closeCalls()).isEqualTo(1));
    }

    @Test
    @DisplayName("an admitted request allocates no response buffer")
    void admittedRequestAllocatesNothing() {
        send(HttpMethod.GET, "/me", "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), TestTokens.validClaims()));

        assertThat(allocator.allocations()).isZero();
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
    @DisplayName("a token verified under a dynamic JWKS is answered 401 once failed reloads pass maximum staleness")
    void filterRefusesStaleJwks() {
        ServiceBoundaryCoreModule sbc = new ServiceBoundaryCoreModule();
        ApiSurfaceRegistry localRegistry = sbc.apiSurfaceRegistry();
        java.util.concurrent.atomic.AtomicBoolean failing = new java.util.concurrent.atomic.AtomicBoolean(false);
        java.util.concurrent.atomic.AtomicLong nanos = new java.util.concurrent.atomic.AtomicLong(100L * 1_000_000_000L);
        JwtAdmissionPolicy policy = JwtAdmissionPolicies.builder()
                .jwksSupplier(() -> {
                    if (failing.get()) {
                        throw new IllegalStateException("JWKS endpoint unreachable");
                    }
                    return TestTokens.jwks(TestTokens.okpJwk("ed-1", ED));
                })
                .expectedIssuer(TestTokens.ISSUER)
                .expectedAudience(TestTokens.AUDIENCE)
                .jwksRefreshInterval(Duration.ofSeconds(60))
                .jwksMinRefreshInterval(Duration.ofSeconds(10))
                .jwksMaxStaleness(Duration.ofSeconds(120))
                .clock(Clock.fixed(Instant.ofEpochSecond(TestTokens.NOW), ZoneOffset.UTC))
                .nanoClock(nanos::get)
                .build();
        JwtValidationModule localModule = new JwtValidationModule(JwtServiceBoundaryBinding.of(sbc.requestFilterChain(), policy, Set.of()));
        localModule.initialize();
        localRegistry.registerRoute(ApiSurfaceRoute.builder()
                .method(HttpMethod.GET)
                .pathPattern("/profile")
                .actionName("GET /profile")
                .requirements(List.of(RouteRequirement.authenticated()))
                .handler(ex -> ex.respond(HttpStatus.OK))
                .build());

        String authHeader = "Bearer " + TestTokens.eddsa("ed-1", ED.getPrivate(), TestTokens.validClaims());

        // First request: valid, 200 OK
        RecordingExchange ex1 = new RecordingExchange(HttpMethod.GET, "/profile", List.of(new HttpHeader("Authorization", authHeader)));
        KernelAllocators.bound(allocator, () -> localRegistry.handle(ex1));
        assertThat(ex1.status).isEqualTo(HttpStatus.OK);

        // Fail subsequent fetches and advance past max staleness
        failing.set(true);
        nanos.addAndGet(Duration.ofSeconds(130).toNanos());

        // Second request: past max staleness, answers 401 UNAUTHORIZED
        RecordingExchange ex2 = new RecordingExchange(HttpMethod.GET, "/profile", List.of(new HttpHeader("Authorization", authHeader)));
        KernelAllocators.bound(allocator, () -> localRegistry.handle(ex2));
        assertThat(ex2.status).isEqualTo(HttpStatus.UNAUTHORIZED);
        localModule.terminate();
    }

    @Test
    @DisplayName("terminate closes a policy the module owns, and never one it does not")
    void terminateClosesAnOwnedPolicy() {
        java.util.concurrent.atomic.AtomicInteger closed = new java.util.concurrent.atomic.AtomicInteger();
        class ClosablePolicy implements JwtAdmissionPolicy, AutoCloseable {
            @Override
            public eu.exeris.caps.jwt.api.JwtValidationResult validate(CharSequence authorizationHeader) {
                throw new UnsupportedOperationException();
            }

            @Override
            public eu.exeris.caps.jwt.api.JwtValidationResult validateToken(CharSequence rawToken) {
                throw new UnsupportedOperationException();
            }

            @Override
            public void close() {
                closed.incrementAndGet();
            }
        }
        ClosablePolicy policy = new ClosablePolicy();
        eu.exeris.caps.jwt.api.AdmissionHostBinding noHost = new eu.exeris.caps.jwt.api.AdmissionHostBinding() {
            @Override
            public String host() {
                return "test";
            }

            @Override
            public void attach() {
            }

            @Override
            public void detach() {
            }
        };

        new JwtValidationModule(noHost).terminate();
        assertThat(closed).hasValue(0);

        JwtValidationModule owner = new JwtValidationModule(noHost, policy);
        owner.terminate();
        owner.terminate();
        assertThat(closed.get()).isGreaterThanOrEqualTo(1);
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
