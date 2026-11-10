package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.memory.LoanedBuffer;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Writes RFC 9457 problem responses ({@code application/problem+json}).
 *
 * <p>The body carries only fixed text chosen by this capability. No exception message, claim value or
 * other request-derived text goes into it, so a rejection tells the caller nothing about why a
 * particular token failed.
 *
 * @since 0.1.0
 */
public final class ProblemResponses {

    private static final ConcurrentHashMap<String, Body[]> BODIES = new ConcurrentHashMap<>();

    private record Body(HttpStatus status, byte[] bytes) {
    }

    private ProblemResponses() {
    }

    /**
     * Returns the encoded body for a status and detail, building it once per pair. The returned array is
     * shared and is only ever read, never handed to the kernel or exposed as writable memory.
     */
    private static byte[] bodyFor(HttpStatus status, String detail) {
        Body[] known = BODIES.get(detail);
        if (known != null) {
            for (Body body : known) {
                if (body.status().equals(status)) {
                    return body.bytes();
                }
            }
        }
        byte[] bytes = ("{\"type\":\"about:blank\",\"title\":\"" + status.reasonPhrase()
                + "\",\"status\":" + status.code() + ",\"detail\":\"" + detail + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        BODIES.merge(detail, new Body[] {new Body(status, bytes)}, (old, added) -> {
            for (Body body : old) {
                if (body.status().equals(status)) {
                    return old;
                }
            }
            Body[] grown = Arrays.copyOf(old, old.length + 1);
            grown[old.length] = added[0];
            return grown;
        });
        return bytes;
    }

    /**
     * Answers the exchange with a problem response.
     *
     * <p>The body is written into a buffer from the kernel allocator bound for the request. Until
     * {@code respond} returns normally the buffer belongs to this method and is released on every
     * other path; once {@code respond} has returned, the engine owns it and this method never touches
     * it again. When no allocator is bound, the answer carries the same status and headers without a
     * body.
     *
     * @param exchange exchange to answer
     * @param status status
     * @param detail fixed detail text
     * @param headers additional headers
     */
    public static void send(HttpExchange exchange, HttpStatus status, String detail, List<HttpHeader> headers) {
        HttpVersion version = exchange.request().version();
        List<HttpHeader> all = new ArrayList<>(headers.size() + 2);
        all.add(new HttpHeader("Cache-Control", "no-store"));
        all.addAll(headers);
        if (!KernelProviders.MEMORY_ALLOCATOR.isBound()) {
            exchange.respond(HttpResponse.noBody(status, version, List.copyOf(all)));
            return;
        }
        byte[] bytes = bodyFor(status, detail);
        all.add(0, new HttpHeader("Content-Type", "application/problem+json"));
        LoanedBuffer buffer = KernelProviders.MEMORY_ALLOCATOR.get().allocateNetwork(bytes.length);
        boolean handedOver = false;
        try {
            if (buffer.capacity() < bytes.length) {
                throw new IllegalStateException("allocator returned a buffer smaller than requested");
            }
            MemorySegment.copy(bytes, 0, buffer.segment(), ValueLayout.JAVA_BYTE, 0L, bytes.length);
            buffer.setSize(bytes.length);
            exchange.respond(new HttpResponse(status, version, List.copyOf(all), buffer));
            handedOver = true;
        } finally {
            if (!handedOver) {
                buffer.close();
            }
        }
    }
}
