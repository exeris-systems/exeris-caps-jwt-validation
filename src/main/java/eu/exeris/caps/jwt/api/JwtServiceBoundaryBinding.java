package eu.exeris.caps.jwt.api;

import eu.exeris.caps.jwt.internal.JwtAdmissionFilter;
import eu.exeris.caps.serviceboundarycore.api.RequestFilterChain;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Binds a {@link JwtAdmissionPolicy} into {@code exeris-caps-service-boundary-core}'s
 * {@link RequestFilterChain}, in the {@code AUTHENTICATION} phase.
 *
 * <p>This type is the only public API type in the capability that names a Service Boundary type, so a
 * composition without {@code service-boundary-core} never loads it.
 *
 * @since 0.1.0
 */
public final class JwtServiceBoundaryBinding implements AdmissionHostBinding {

    /**
     * Comma-separated routes, each {@code "METHOD /path/{template}"}, that admit a request without a token.
     * Every other route requires one. Default: none.
     */
    public static final String KEY_ANONYMOUS_ROUTES = "exeris.caps.jwt.anonymous-routes";

    private final RequestFilterChain chain;
    private final JwtAdmissionFilter filter;

    private JwtServiceBoundaryBinding(RequestFilterChain chain, JwtAdmissionFilter filter) {
        this.chain = chain;
        this.filter = filter;
    }

    /**
     * Creates a binding of {@code policy} into {@code chain}.
     *
     * @param chain the Service Boundary filter chain
     * @param policy token verification policy
     * @param anonymousRoutes routes, as {@code "METHOD /path/{template}"}, that admit a request without a token
     * @return the binding; attach it through the capability module
     */
    public static JwtServiceBoundaryBinding of(RequestFilterChain chain, JwtAdmissionPolicy policy,
                                               Set<String> anonymousRoutes) {
        Objects.requireNonNull(chain, "chain");
        return new JwtServiceBoundaryBinding(chain, new JwtAdmissionFilter(policy, anonymousRoutes));
    }

    /**
     * Reads {@link #KEY_ANONYMOUS_ROUTES}.
     *
     * @param properties configuration
     * @return the anonymous routes
     */
    public static Set<String> anonymousRoutes(Map<String, String> properties) {
        String value = properties.get(KEY_ANONYMOUS_ROUTES);
        Set<String> routes = new LinkedHashSet<>();
        if (value != null) {
            for (String entry : value.split(",")) {
                String route = entry.strip().replaceAll("\\s+", " ");
                if (!route.isEmpty()) {
                    if (route.indexOf(' ') <= 0) {
                        throw new IllegalStateException(KEY_ANONYMOUS_ROUTES + " entry is not \"METHOD /path\": " + route);
                    }
                    routes.add(route);
                }
            }
        }
        return Set.copyOf(routes);
    }

    @Override
    public String host() {
        return "service-boundary-core RequestFilterChain";
    }

    @Override
    public void attach() {
        chain.registerFilter(filter);
    }

    @Override
    public void detach() {
        chain.unregisterFilter(filter);
    }
}
