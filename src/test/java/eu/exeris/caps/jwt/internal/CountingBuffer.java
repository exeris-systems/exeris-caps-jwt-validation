package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.memory.LoanedBuffer;

import java.lang.foreign.MemorySegment;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Wraps a kernel buffer to count every {@code close()} call, which the kernel's own idempotent close
 * would otherwise hide, and to inject the failures a driver can produce.
 */
public final class CountingBuffer implements LoanedBuffer {

    private final LoanedBuffer delegate;
    private final long reportedCapacity;
    private final boolean failSetSize;
    private final AtomicInteger closeCalls = new AtomicInteger();

    CountingBuffer(LoanedBuffer delegate, long reportedCapacity, boolean failSetSize) {
        this.delegate = delegate;
        this.reportedCapacity = reportedCapacity;
        this.failSetSize = failSetSize;
    }

    public int closeCalls() {
        return closeCalls.get();
    }

    @Override
    public MemorySegment segment() {
        return reportedCapacity >= 0 && reportedCapacity < delegate.segment().byteSize()
                ? delegate.segment().asSlice(0, reportedCapacity)
                : delegate.segment();
    }

    @Override
    public long size() {
        return delegate.size();
    }

    @Override
    public long capacity() {
        return reportedCapacity >= 0 ? reportedCapacity : delegate.capacity();
    }

    @Override
    public LoanedBuffer slice(long offset, long length) {
        return delegate.slice(offset, length);
    }

    @Override
    public LoanedBuffer view() {
        return delegate.view();
    }

    @Override
    public LoanedBuffer peek(long offset, long length) {
        return delegate.peek(offset, length);
    }

    @Override
    public void retain() {
        delegate.retain();
    }

    @Override
    public void close() {
        closeCalls.incrementAndGet();
        delegate.close();
    }

    @Override
    public int refCount() {
        return delegate.refCount();
    }

    @Override
    public void setSize(long newSize) {
        if (failSetSize) {
            throw new IllegalStateException("setSize failed");
        }
        delegate.setSize(newSize);
    }

    @Override
    public boolean isAlive() {
        return delegate.isAlive();
    }

    @Override
    public void addCloseAction(Runnable action) {
        delegate.addCloseAction(action);
    }
}
