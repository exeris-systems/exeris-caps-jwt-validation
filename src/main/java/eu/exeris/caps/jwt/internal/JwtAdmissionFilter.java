package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtPrincipal;
import eu.exeris.caps.jwt.api.JwtValidationResult;
import eu.exeris.caps.serviceboundarycore.api.AdmissionContext;
import eu.exeris.caps.serviceboundarycore.api.AdmissionFilter;
import eu.exeris.caps.serviceboundarycore.api.AdmissionPhase;
import eu.exeris.caps.serviceboundarycore.api.RouteMatch;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpStatus;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Service Boundary admission filter that authenticates the caller from a bearer access token.
 *
 * <p>On a verified token it records a {@link JwtPrincipal} through {@link AdmissionContext}, which is how
 * the principal reaches the handler's {@code RequestContext}. On any failure it answers 401 with a fixed
 * problem body. A route listed as anonymous admits a request without a token; a token that is present
 * is verified on every route, so a bad credential is never silently treated as no credential.
 *
 * @since 0.1.0
 */
public final class JwtAdmissionFilter implements AdmissionFilter {

    /** Filter name in the chain. */
    public static final String NAME = "jwt-validation";

    private static final String DETAIL = "The request lacks valid bearer credentials.";
    private static final List<HttpHeader> CHALLENGE = List.of(new HttpHeader("WWW-Authenticate", "Bearer"));
    private static final List<HttpHeader> INVALID_TOKEN_CHALLENGE =
            List.of(new HttpHeader("WWW-Authenticate", "Bearer error=\"invalid_token\""));

    private final JwtAdmissionPolicy policy;
    private final Set<String> anonymousRoutes;

    /**
     * @param policy token verification policy
     * @param anonymousRoutes routes, as {@code "METHOD /path/{template}"}, that admit a request without a token
     */
    public JwtAdmissionFilter(JwtAdmissionPolicy policy, Set<String> anonymousRoutes) {
        this.policy = Objects.requireNonNull(policy, "policy");
        this.anonymousRoutes = Set.copyOf(anonymousRoutes);
    }

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public AdmissionPhase phase() {
        return AdmissionPhase.AUTHENTICATION;
    }

    @Override
    public boolean filter(HttpExchange exchange, RouteMatch routeMatch) {
        List<String> authorization = exchange.request().headers().stream()
                .filter(h -> h.nameEqualsIgnoreCase("Authorization"))
                .map(HttpHeader::value)
                .toList();
        if (authorization.isEmpty()) {
            if (anonymousRoutes.contains(routeKey(routeMatch))) {
                return true;
            }
            ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, DETAIL, CHALLENGE);
            return false;
        }
        if (authorization.size() > 1) {
            ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, DETAIL, INVALID_TOKEN_CHALLENGE);
            return false;
        }
        JwtValidationResult result = policy.validate(authorization.getFirst());
        Optional<JwtPrincipal> principal = JwtPrincipal.from(result);
        if (principal.isEmpty()) {
            ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, DETAIL, INVALID_TOKEN_CHALLENGE);
            return false;
        }
        AdmissionContext.current().authenticate(principal.get());
        return true;
    }

    /**
     * The key a route is listed under in the anonymous-route set.
     *
     * @param routeMatch matched route
     * @return {@code "METHOD /path/{template}"}
     */
    public static String routeKey(RouteMatch routeMatch) {
        return routeMatch.route().method().name() + " " + routeMatch.route().pathPattern();
    }
}
