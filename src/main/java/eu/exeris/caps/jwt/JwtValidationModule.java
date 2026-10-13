package eu.exeris.caps.jwt;

import eu.exeris.caps.jwt.api.AdmissionHostBinding;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.serviceboundarycore.api.RequestFilterChain;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Duration;

/**
 * The capability declaration and lifecycle owner for {@code exeris-caps-jwt-validation}.
 *
 * <p>The token check runs in an admission host (ADR-099 obligation 4): {@code service-boundary-core}'s
 * {@link RequestFilterChain}, bound through {@code JwtServiceBoundaryBinding}, or the gateway policy chain.
 * Both are optional edges; with no host bound the module refuses to initialise, since a check that runs
 * nowhere admits every request.
 *
 * <p>The module's own signatures name no type of an optional capability, so it loads whichever host is
 * absent.
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = JwtAdmissionPolicy.class, version = "2.0.0")
@Requires(service = RequestFilterChain.class, versionRange = "[1.1.0,2.0.0)", optional = true)
public final class JwtValidationModule implements CapabilityLifecycleHooks {

    private final AdmissionHostBinding binding;

    /**
     * Reflective constructor of the composition runtime. It binds no host, so {@link #initialize()} refuses;
     * a composition supplies the binding through {@link #JwtValidationModule(AdmissionHostBinding)}.
     */
    public JwtValidationModule() {
        this(null);
    }

    /**
     * @param binding where the token check is installed; null leaves the module unable to initialise
     */
    public JwtValidationModule(AdmissionHostBinding binding) {
        this.binding = binding;
    }

    @Override
    public void initialize() {
        if (binding == null) {
            throw new IllegalStateException(
                    "exeris-caps-jwt-validation has no admission host: bind it into service-boundary-core's "
                            + "RequestFilterChain (JwtServiceBoundaryBinding) or into the gateway policy chain");
        }
        binding.attach();
    }

    @Override
    public void ready() {
        // The check is live from initialize(); nothing further to do.
    }

    @Override
    public void drain(Duration remaining) {
        // Requests still in flight are verified until terminate() detaches the check.
    }

    @Override
    public void terminate() {
        if (binding != null) {
            binding.detach();
        }
    }
}
