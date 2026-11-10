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
@Provides(service = JwtAdmissionPolicy.class, version = "0.1.0")
@Requires(service = RequestFilterChain.class, versionRange = "[0.1.0,0.2.0)", optional = true)
public final class JwtValidationModule implements CapabilityLifecycleHooks {

    private final AdmissionHostBinding binding;
    private final JwtAdmissionPolicy ownedPolicy;

    /**
     * Reflective constructor of the composition runtime. It binds no host, so {@link #initialize()} refuses;
     * a composition supplies the binding through {@link #JwtValidationModule(AdmissionHostBinding)}.
     */
    public JwtValidationModule() {
        this(null);
    }

    /**
     * Creates a module that installs its check through {@code binding}.
     *
     * @param binding where the token check is installed; null leaves the module unable to initialise
     */
    public JwtValidationModule(AdmissionHostBinding binding) {
        this(binding, null);
    }

    /**
     * Creates a module that installs its check through {@code binding} and owns {@code policy}'s background
     * work: when the policy is {@link AutoCloseable}, {@link #terminate()} closes it after the check is
     * detached. The one-argument constructor leaves the policy to its caller.
     *
     * @param binding where the token check is installed; null leaves the module unable to initialise
     * @param policy the policy the binding installs; may be null
     */
    public JwtValidationModule(AdmissionHostBinding binding, JwtAdmissionPolicy policy) {
        this.binding = binding;
        this.ownedPolicy = policy;
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
        // The check is live from initialize(); the policy's refresher starts when the policy is built.
    }

    @Override
    public void drain(Duration remaining) {
        // Requests still in flight are verified until terminate() detaches the check, so the refresher
        // keeps running until then.
    }

    @Override
    public void terminate() {
        try {
            if (binding != null) {
                binding.detach();
            }
        } finally {
            if (ownedPolicy instanceof AutoCloseable closeable) {
                try {
                    closeable.close();
                } catch (Exception e) {
                    System.getLogger(JwtValidationModule.class.getName())
                            .log(System.Logger.Level.WARNING, "Closing the JWT admission policy failed", e);
                }
            }
        }
    }
}
