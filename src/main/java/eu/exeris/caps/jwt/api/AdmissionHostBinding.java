package eu.exeris.caps.jwt.api;

/**
 * Where the capability's admission check is installed: the Service Boundary {@code RequestFilterChain},
 * or the gateway policy chain when that host exists (ADR-099 obligation 4).
 *
 * <p>The capability module attaches its binding when it initialises and detaches it when it terminates.
 * A module with no binding refuses to initialise, because a token check that runs nowhere admits
 * everything.
 *
 * @since 0.1.0
 */
public interface AdmissionHostBinding {

    /**
     * Names the host this binding installs the check in.
     *
     * @return the host's name, for diagnostics
     */
    String host();

    /** Installs the check in the host. */
    void attach();

    /** Removes the check from the host. */
    void detach();
}
