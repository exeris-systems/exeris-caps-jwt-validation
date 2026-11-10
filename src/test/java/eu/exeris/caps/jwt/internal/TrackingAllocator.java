package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.memory.AllocationHint;
import eu.exeris.kernel.spi.memory.LoanedBuffer;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import eu.exeris.kernel.spi.memory.MemoryStats;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A real kernel allocator behind a counter: how many buffers were handed out, how many were finally
 * released, and how often each one was closed. Failure modes are injected per instance.
 */
public final class TrackingAllocator implements MemoryAllocator {

    private final MemoryAllocator base;
    private final boolean shortCapacity;
    private final boolean failSetSize;
    private final AtomicInteger finalReleases = new AtomicInteger();
    private final List<CountingBuffer> buffers = Collections.synchronizedList(new ArrayList<>());
    private final List<Integer> requestedSizes = Collections.synchronizedList(new ArrayList<>());

    public TrackingAllocator(MemoryAllocator base) {
        this(base, false, false);
    }

    private TrackingAllocator(MemoryAllocator base, boolean shortCapacity, boolean failSetSize) {
        this.base = base;
        this.shortCapacity = shortCapacity;
        this.failSetSize = failSetSize;
    }

    /** An allocator whose buffers report one byte less capacity than was requested. */
    public static TrackingAllocator withShortCapacity(MemoryAllocator base) {
        return new TrackingAllocator(base, true, false);
    }

    /** An allocator whose buffers throw from {@code setSize}. */
    public static TrackingAllocator withFailingSetSize(MemoryAllocator base) {
        return new TrackingAllocator(base, false, true);
    }

    public int allocations() {
        return buffers.size();
    }

    public int finalReleases() {
        return finalReleases.get();
    }

    public int outstanding() {
        return allocations() - finalReleases();
    }

    public List<CountingBuffer> buffers() {
        synchronized (buffers) {
            return List.copyOf(buffers);
        }
    }

    public List<Integer> requestedSizes() {
        synchronized (requestedSizes) {
            return List.copyOf(requestedSizes);
        }
    }

    private LoanedBuffer track(LoanedBuffer real, long requested) {
        real.addCloseAction(finalReleases::incrementAndGet);
        long reported = shortCapacity ? requested - 1 : -1;
        CountingBuffer wrapped = new CountingBuffer(real, reported, failSetSize);
        buffers.add(wrapped);
        return wrapped;
    }

    @Override
    public LoanedBuffer allocateNetwork(int estimatedBytes) {
        requestedSizes.add(estimatedBytes);
        return track(base.allocateNetwork(estimatedBytes), estimatedBytes);
    }

    @Override
    public LoanedBuffer allocate(AllocationHint hint) {
        requestedSizes.add(hint.sizeBytes());
        return track(base.allocate(hint), hint.sizeBytes());
    }

    @Override
    public LoanedBuffer allocateCarrierSlab(int carrierIndex) {
        LoanedBuffer real = base.allocateCarrierSlab(carrierIndex);
        return track(real, real.capacity());
    }

    @Override
    public LoanedBuffer allocateInfrastructure(long sizeBytes) {
        return track(base.allocateInfrastructure(sizeBytes), sizeBytes);
    }

    @Override
    public MemoryStats stats() {
        return base.stats();
    }

    @Override
    public void close() {
        // the base allocator belongs to the test class
    }
}
