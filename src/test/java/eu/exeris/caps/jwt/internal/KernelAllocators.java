package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.memory.LeakDetectionMode;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import eu.exeris.kernel.spi.memory.MemoryProvider;
import eu.exeris.kernel.spi.memory.MemoryProviderConfig;

import java.util.ServiceLoader;

/** Test access to a real kernel allocator and to the request-scoped slot the engine binds it to. */
public final class KernelAllocators {

    private KernelAllocators() {
    }

    /** A real allocator with the strictest leak detection, found through the provider registry. */
    public static MemoryAllocator create() {
        return ServiceLoader.load(MemoryProvider.class).findFirst().orElseThrow()
                .createAllocator(MemoryProviderConfig.defaults().withLeakDetection(LeakDetectionMode.PARANOID));
    }

    /** Runs {@code action} the way the engine runs a handler: with the allocator bound for the request. */
    public static void bound(MemoryAllocator allocator, Runnable action) {
        ScopedValue.where(KernelProviders.MEMORY_ALLOCATOR, allocator).run(action);
    }
}
