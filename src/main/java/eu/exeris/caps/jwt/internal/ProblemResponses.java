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
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

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

    /**
     * Upper bound on the number of cached bodies. Once reached, a body for an uncached status and detail
     * is built per call and not stored. Insertion checks the count before it inserts, without a lock
     * spanning the two, so concurrent callers can overshoot the bound by at most their own number.
     */
    static final int MAX_CACHED_BODIES = 64;

    private static final ConcurrentHashMap<HttpStatus, ConcurrentHashMap<String, byte[]>> BODIES =
            new ConcurrentHashMap<>();
    private static final AtomicInteger CACHED = new AtomicInteger();

    private ProblemResponses() {
    }

    /**
     * Header lists for one fixed set of additional headers, built once and shared immutably. The
     * {@code withBody} list leads with the content type; both lists carry {@code Cache-Control}
     * before the additional headers.
     *
     * @param withBody headers of a response that carries a body
     * @param withoutBody headers of a response without a body
     */
    public record Headers(List<HttpHeader> withBody, List<HttpHeader> withoutBody) {

        /**
         * Builds the shared lists for the given additional headers.
         *
         * @param additional additional headers, in the order they are sent
         * @return the shared lists
         */
        public static Headers of(List<HttpHeader> additional) {
            List<HttpHeader> bare = new ArrayList<>(additional.size() + 2);
            bare.add(new HttpHeader("Cache-Control", "no-store"));
            bare.addAll(additional);
            List<HttpHeader> full = new ArrayList<>(bare.size() + 1);
            full.add(new HttpHeader("Content-Type", "application/problem+json"));
            full.addAll(bare);
            return new Headers(List.copyOf(full), List.copyOf(bare));
        }
    }

    private static byte[] encode(HttpStatus status, String detail) {
        return ("{\"type\":\"about:blank\",\"title\":\"" + status.reasonPhrase()
                + "\",\"status\":" + status.code() + ",\"detail\":\"" + detail + "\"}")
                .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Returns the encoded body for a status and detail. At most {@link #MAX_CACHED_BODIES} bodies are
     * kept. The returned array is shared and is only ever read, never handed to the kernel or exposed
     * as writable memory.
     *
     * <p>Lookups use {@code get}; inserts use {@code putIfAbsent} and only while the count is under the
     * bound, so no mapping function runs, no entry is removed, and a caller holds at most one bin
     * lock at a time, only for the duration of a single insert.
     */
    private static byte[] bodyFor(HttpStatus status, String detail) {
        ConcurrentHashMap<String, byte[]> byDetail = BODIES.get(status);
        if (byDetail != null) {
            byte[] cached = byDetail.get(detail);
            if (cached != null) {
                return cached;
            }
        }
        byte[] bytes = encode(status, detail);
        if (CACHED.get() >= MAX_CACHED_BODIES) {
            return bytes;
        }
        if (byDetail == null) {
            ConcurrentHashMap<String, byte[]> fresh = new ConcurrentHashMap<>();
            byDetail = BODIES.putIfAbsent(status, fresh);
            if (byDetail == null) {
                byDetail = fresh;
            }
        }
        byte[] earlier = byDetail.putIfAbsent(detail, bytes);
        if (earlier != null) {
            return earlier;
        }
        CACHED.incrementAndGet();
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
        all.add(0, new HttpHeader("Content-Type", "application/problem+json"));
        respondWithBody(exchange, status, version, bodyFor(status, detail), List.copyOf(all));
    }

    /**
     * Answers the exchange with a problem response whose headers were built once by
     * {@link Headers#of}. Ownership of the body buffer is as for the list-taking overload.
     *
     * @param exchange exchange to answer
     * @param status status
     * @param detail fixed detail text
     * @param headers shared header lists
     */
    public static void send(HttpExchange exchange, HttpStatus status, String detail, Headers headers) {
        HttpVersion version = exchange.request().version();
        if (!KernelProviders.MEMORY_ALLOCATOR.isBound()) {
            exchange.respond(HttpResponse.noBody(status, version, headers.withoutBody()));
            return;
        }
        respondWithBody(exchange, status, version, bodyFor(status, detail), headers.withBody());
    }

    private static void respondWithBody(HttpExchange exchange, HttpStatus status, HttpVersion version,
            byte[] bytes, List<HttpHeader> headers) {
        LoanedBuffer buffer = KernelProviders.MEMORY_ALLOCATOR.get().allocateNetwork(bytes.length);
        boolean handedOver = false;
        try {
            if (buffer.capacity() < bytes.length) {
                throw new IllegalStateException("allocator returned a buffer smaller than requested");
            }
            MemorySegment.copy(bytes, 0, buffer.segment(), ValueLayout.JAVA_BYTE, 0L, bytes.length);
            buffer.setSize(bytes.length);
            exchange.respond(new HttpResponse(status, version, headers, buffer));
            handedOver = true;
        } finally {
            if (!handedOver) {
                buffer.close();
            }
        }
    }
}
