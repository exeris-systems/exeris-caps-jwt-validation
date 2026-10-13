package eu.exeris.caps.jwt;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;

/**
 * The capability declaration for {@code exeris-caps-jwt-validation}.
 *
 * <p>Carries the {@code @CapabilityModule} and {@code @Provides} contract annotations
 * for the build-time codegen pipeline and composition conductor.
 *
 * @since 0.1.0
 */
@CapabilityModule
@Provides(service = JwtAdmissionPolicy.class, version = "1.0.0")
public final class JwtValidationModule {

    private JwtValidationModule() {
        // Declaration carrier only — never constructed.
    }
}
