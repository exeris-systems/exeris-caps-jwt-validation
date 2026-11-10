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
    private final boolean dirty;
    private final AtomicInteger networkCalls = new AtomicInteger();
    private final AtomicInteger finalReleases = new AtomicInteger();
    private final List<CountingBuffer> buffers = Collections.synchronizedList(new ArrayList<>());
    private final List<Integer> requestedSizes = Collections.synchronizedList(new ArrayList<>());
    private final List<AllocationHint> requestedHints = Collections.synchronizedList(new ArrayList<>());

    public TrackingAllocator(MemoryAllocator base) {
        this(base, false, false, false);
    }

    private TrackingAllocator(MemoryAllocator base, boolean shortCapacity, boolean failSetSize, boolean dirty) {
        this.base = base;
        this.shortCapacity = shortCapacity;
        this.failSetSize = failSetSize;
        this.dirty = dirty;
    }

    /** An allocator whose buffers report a capacity below any body, as a faulty driver might. */
    public static TrackingAllocator withShortCapacity(MemoryAllocator base) {
        return new TrackingAllocator(base, true, false, false);
    }

    /** An allocator whose buffers throw from {@code setSize}. */
    public static TrackingAllocator withFailingSetSize(MemoryAllocator base) {
        return new TrackingAllocator(base, false, true, false);
    }

    /**
     * An allocator that hands out exactly what a hint guarantees and nothing more: the buffer reports a
     * capacity of {@code hint.sizeBytes()}, its segment is confined to that many bytes so a write past
     * the guarantee fails, and every byte of it holds a non-zero pattern so a reader that assumes zeroed
     * memory is caught.
     */
    public static TrackingAllocator withDirtyBuffers(MemoryAllocator base) {
        return new TrackingAllocator(base, false, false, true);
    }

    /** The byte every position of a dirty buffer holds when it is handed out. */
    public static final byte DIRTY = (byte) 0xA5;

    /** Number of times the byte-size network allocation was asked for. */
    public int networkCalls() {
        return networkCalls.get();
    }

    /** The hints passed to {@code allocate}, in call order. */
    public List<AllocationHint> hints() {
        synchronized (requestedHints) {
            return List.copyOf(requestedHints);
        }
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
        long reported = shortCapacity ? 0 : dirty ? requested : -1;
        if (dirty) {
            if (real.capacity() < requested) {
                throw new AssertionError("the real allocator broke its hint guarantee");
            }
            real.segment().asSlice(0, requested).fill(DIRTY);
        }
        CountingBuffer wrapped = new CountingBuffer(real, reported, failSetSize);
        buffers.add(wrapped);
        return wrapped;
    }

    @Override
    public LoanedBuffer allocateNetwork(int estimatedBytes) {
        networkCalls.incrementAndGet();
        requestedSizes.add(estimatedBytes);
        throw new AssertionError("allocateNetwork(" + estimatedBytes + ") was called; a body is allocated by hint");
    }

    @Override
    public LoanedBuffer allocate(AllocationHint hint) {
        requestedSizes.add(hint.sizeBytes());
        requestedHints.add(hint);
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
