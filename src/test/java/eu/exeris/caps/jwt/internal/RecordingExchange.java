package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.memory.LoanedBuffer;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

/**
 * An exchange that plays the engine: it answers once, takes ownership of the body, copies the
 * {@code size()} bytes it was handed and releases the buffer.
 *
 * <p>A second {@code respond} is rejected without touching its body, as the kernel's exchanges do.
 */
public final class RecordingExchange implements HttpExchange {

    /** How the engine treats the response it is given. */
    public enum Mode {
        /** Copies and releases the body inside {@code respond} (HTTP/1.1 shape). */
        RELEASE_IMMEDIATELY,
        /** Keeps the response and releases the body only on {@link #completeDeferred()} (HTTP/2 shape). */
        RELEASE_DEFERRED,
        /** Throws before taking ownership; the body is untouched. */
        REJECT_BEFORE_TAKE,
        /** Takes ownership, copies and releases the body, then throws. */
        FAIL_AFTER_RELEASE
    }

    private final HttpRequest request;
    private final Mode mode;
    private int respondCalls;

    public HttpResponse response;
    public HttpStatus status;
    /** The bytes the engine read from the body; null when no body was handed over. */
    public byte[] bodyBytes;
    /** Body state observed at the moment {@code respond} was called. */
    public Boolean bodyAliveAtRespond;
    public Integer bodyRefCountAtRespond;
    public Long bodySizeAtRespond;
    public Long bodyCapacityAtRespond;

    public RecordingExchange(HttpMethod method, String path, List<HttpHeader> headers) {
        this(method, path, headers, HttpVersion.HTTP_1_1, Mode.RELEASE_IMMEDIATELY);
    }

    public RecordingExchange(HttpMethod method, String path, List<HttpHeader> headers, HttpVersion version, Mode mode) {
        this.request = HttpRequest.noBody(method, path, version, headers);
        this.mode = mode;
    }

    @Override
    public HttpRequest request() {
        return request;
    }

    public int respondCalls() {
        return respondCalls;
    }

    @Override
    public void respond(HttpResponse response) {
        respondCalls++;
        if (respondCalls > 1 || mode == Mode.REJECT_BEFORE_TAKE) {
            throw new IllegalStateException("response already sent or rejected");
        }
        this.response = response;
        this.status = response.status();
        LoanedBuffer body = response.body();
        if (body != null) {
            bodyAliveAtRespond = body.isAlive();
            bodyRefCountAtRespond = body.refCount();
            bodySizeAtRespond = body.size();
            bodyCapacityAtRespond = body.capacity();
        }
        if (mode == Mode.RELEASE_DEFERRED) {
            return;
        }
        takeAndRelease();
        if (mode == Mode.FAIL_AFTER_RELEASE) {
            throw new IllegalStateException("write failed after the body was released");
        }
    }

    /** Plays the engine's late write of a deferred response: reads the body, then releases it. */
    public void completeDeferred() {
        takeAndRelease();
    }

    private void takeAndRelease() {
        LoanedBuffer body = response.body();
        if (body == null) {
            return;
        }
        try (body) {
            bodyBytes = body.segment().asSlice(0, body.size()).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    public Optional<String> header(String name) {
        return response.headers().stream().filter(h -> h.nameEqualsIgnoreCase(name)).map(HttpHeader::value).findFirst();
    }

    public String body() {
        return new String(bodyBytes, StandardCharsets.UTF_8);
    }

    /** The live body of a deferred response, for tests that act on it before release. */
    public MemorySegment liveSegment() {
        return response.body().segment();
    }
}
