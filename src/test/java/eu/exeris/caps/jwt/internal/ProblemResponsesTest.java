package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import eu.exeris.kernel.spi.memory.MemoryStats;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.memory.LoanedBuffer;
import eu.exeris.kernel.spi.memory.MemoryProvider;
import eu.exeris.kernel.spi.memory.MemoryProviderConfig;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("problem responses hand their body to the kernel in an allocator buffer")
class ProblemResponsesTest {

    private static final String DETAIL = "The request lacks valid bearer credentials.";
    private static final List<HttpHeader> CHALLENGE = List.of(new HttpHeader("WWW-Authenticate", "Bearer"));

    private static MemoryAllocator base;

    @BeforeAll
    static void openAllocator() {
        base = KernelAllocators.create();
    }

    @AfterAll
    static void closeAllocator() {
        base.close();
    }

    private static String expectedBody(HttpStatus status, String detail) {
        return "{\"type\":\"about:blank\",\"title\":\"" + status.reasonPhrase() + "\",\"status\":" + status.code()
                + ",\"detail\":\"" + detail + "\"}";
    }

    private static RecordingExchange exchange(HttpVersion version, RecordingExchange.Mode mode) {
        return new RecordingExchange(HttpMethod.GET, "/me", List.of(), version, mode);
    }

    private static void send(TrackingAllocator allocator, RecordingExchange exchange, HttpStatus status) {
        KernelAllocators.bound(allocator, () -> ProblemResponses.send(exchange, status, DETAIL, CHALLENGE));
    }

    @Test
    @DisplayName("the bytes handed to the kernel equal the encoded problem body, for each status")
    void bytesMatch() {
        for (HttpStatus status : List.of(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN, HttpStatus.TOO_MANY_REQUESTS,
                HttpStatus.SERVICE_UNAVAILABLE)) {
            TrackingAllocator allocator = new TrackingAllocator(base);
            RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_IMMEDIATELY);

            send(allocator, exchange, status);

            byte[] expected = expectedBody(status, DETAIL).getBytes(StandardCharsets.UTF_8);
            assertThat(exchange.status).isEqualTo(status);
            assertThat(exchange.bodySizeAtRespond).isEqualTo(expected.length);
            assertThat(exchange.bodyBytes).isEqualTo(expected);
        }
    }

    @Test
    @DisplayName("a multi-byte body is sized in bytes, not characters")
    void sizeIsInBytes() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_IMMEDIATELY);
        String detail = "Brak łącznego tokenu";

        KernelAllocators.bound(allocator,
                () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, detail, CHALLENGE));

        byte[] expected = expectedBody(HttpStatus.UNAUTHORIZED, detail).getBytes(StandardCharsets.UTF_8);
        assertThat(exchange.bodySizeAtRespond).isEqualTo(expected.length);
        assertThat(exchange.bodyBytes).isEqualTo(expected);
    }

    @Test
    @DisplayName("Content-Length is absent or equals the body size; Content-Type and challenge headers are kept")
    void headers() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_IMMEDIATELY);

        send(allocator, exchange, HttpStatus.UNAUTHORIZED);

        assertThat(exchange.header("Content-Length")).isIn(java.util.Optional.empty(),
                java.util.Optional.of(String.valueOf(exchange.bodyBytes.length)));
        assertThat(exchange.response.headers().stream().filter(h -> h.nameEqualsIgnoreCase("Content-Type")).toList())
                .hasSize(1);
        assertThat(exchange.header("Content-Type")).contains("application/problem+json");
        assertThat(exchange.header("WWW-Authenticate")).contains("Bearer");
        assertThat(exchange.header("Cache-Control")).contains("no-store");
    }

    @Test
    @DisplayName("the response carries the request's protocol version")
    void versionPreserved() {
        for (HttpVersion version : List.of(HttpVersion.HTTP_1_1, HttpVersion.HTTP_2)) {
            TrackingAllocator allocator = new TrackingAllocator(base);
            RecordingExchange exchange = exchange(version, RecordingExchange.Mode.RELEASE_IMMEDIATELY);

            send(allocator, exchange, HttpStatus.UNAUTHORIZED);

            assertThat(exchange.response.version()).isEqualTo(version);
        }
    }

    @Test
    @DisplayName("the body is one kernel allocation of exactly the encoded length, and it is the buffer handed over")
    void kernelBufferOnly() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_DEFERRED);

        send(allocator, exchange, HttpStatus.UNAUTHORIZED);

        int length = expectedBody(HttpStatus.UNAUTHORIZED, DETAIL).getBytes(StandardCharsets.UTF_8).length;
        assertThat(allocator.allocations()).isEqualTo(1);
        assertThat(allocator.requestedSizes()).containsExactly(length);
        assertThat(exchange.response.body()).isSameAs(allocator.buffers().getFirst());
        assertThat(exchange.response.body().segment().isNative()).isTrue();
        exchange.completeDeferred();
    }

    @Test
    @DisplayName("on success the buffer is released exactly once and never closed by the caller")
    void releasedOnceOnSuccess() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_IMMEDIATELY);

        send(allocator, exchange, HttpStatus.UNAUTHORIZED);

        assertThat(allocator.finalReleases()).isEqualTo(1);
        assertThat(allocator.outstanding()).isZero();
        assertThat(allocator.buffers().getFirst().closeCalls()).isEqualTo(1);
    }

    @Test
    @DisplayName("when respond rejects before taking the body, the buffer is released once and the failure reaches the caller")
    void releasedWhenRespondRejects() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.REJECT_BEFORE_TAKE);

        assertThatThrownBy(() -> send(allocator, exchange, HttpStatus.UNAUTHORIZED))
                .isInstanceOf(IllegalStateException.class);

        assertThat(allocator.allocations()).isEqualTo(1);
        assertThat(allocator.finalReleases()).isEqualTo(1);
        assertThat(allocator.outstanding()).isZero();
        assertThat(allocator.buffers().getFirst().closeCalls()).isEqualTo(1);
    }

    @Test
    @DisplayName("a second answer is rejected without touching the first answer's body or leaking the second")
    void secondRespondDoesNotDisturbTheFirst() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_2, RecordingExchange.Mode.RELEASE_DEFERRED);

        send(allocator, exchange, HttpStatus.UNAUTHORIZED);
        assertThatThrownBy(() -> send(allocator, exchange, HttpStatus.UNAUTHORIZED))
                .isInstanceOf(IllegalStateException.class);

        assertThat(allocator.allocations()).isEqualTo(2);
        assertThat(allocator.finalReleases()).isEqualTo(1);
        assertThat(allocator.buffers().getFirst().isAlive()).isTrue();
        assertThat(allocator.buffers().getFirst().closeCalls()).isZero();
        exchange.completeDeferred();
        assertThat(allocator.outstanding()).isZero();
        assertThat(exchange.bodyBytes).isEqualTo(expectedBody(HttpStatus.UNAUTHORIZED, DETAIL).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("when the engine fails after releasing the body, nothing leaks and any further close is a no-op")
    void noLeakWhenEngineFailsAfterRelease() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.FAIL_AFTER_RELEASE);

        assertThatThrownBy(() -> send(allocator, exchange, HttpStatus.UNAUTHORIZED))
                .isInstanceOf(IllegalStateException.class);

        assertThat(allocator.finalReleases()).isEqualTo(1);
        assertThat(allocator.outstanding()).isZero();
        assertThat(allocator.buffers().getFirst().closeCalls()).isLessThanOrEqualTo(2);
    }

    @Test
    @DisplayName("a buffer smaller than requested is released once and nothing is handed over")
    void shortCapacityIsReleased() {
        TrackingAllocator allocator = TrackingAllocator.withShortCapacity(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_IMMEDIATELY);

        assertThatThrownBy(() -> send(allocator, exchange, HttpStatus.UNAUTHORIZED))
                .isInstanceOf(IllegalStateException.class);

        assertThat(exchange.respondCalls()).isZero();
        assertThat(allocator.allocations()).isEqualTo(1);
        assertThat(allocator.finalReleases()).isEqualTo(1);
        assertThat(allocator.buffers().getFirst().closeCalls()).isEqualTo(1);
    }

    @Test
    @DisplayName("a failure setting the size is released once and nothing is handed over")
    void setSizeFailureIsReleased() {
        TrackingAllocator allocator = TrackingAllocator.withFailingSetSize(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_IMMEDIATELY);

        assertThatThrownBy(() -> send(allocator, exchange, HttpStatus.UNAUTHORIZED))
                .isInstanceOf(IllegalStateException.class);

        assertThat(exchange.respondCalls()).isZero();
        assertThat(allocator.finalReleases()).isEqualTo(1);
        assertThat(allocator.buffers().getFirst().closeCalls()).isEqualTo(1);
    }

    @Test
    @DisplayName("a failure while building the headers leaves no buffer behind")
    void headerFailureLeavesNoBuffer() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_IMMEDIATELY);
        List<HttpHeader> failing = new AbstractList<>() {
            @Override
            public HttpHeader get(int index) {
                throw new IllegalStateException("headers unavailable");
            }

            @Override
            public int size() {
                return 1;
            }
        };

        assertThatThrownBy(() -> KernelAllocators.bound(allocator,
                () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, DETAIL, failing)))
                .isInstanceOf(IllegalStateException.class);

        assertThat(exchange.respondCalls()).isZero();
        assertThat(allocator.outstanding()).isZero();
    }

    @Test
    @DisplayName("a deferred engine (HTTP/2) finds the body alive, with one reference, after the handler returned")
    void bodySurvivesTheHandler() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange exchange = exchange(HttpVersion.HTTP_2, RecordingExchange.Mode.RELEASE_DEFERRED);

        send(allocator, exchange, HttpStatus.UNAUTHORIZED);

        assertThat(exchange.bodyAliveAtRespond).isTrue();
        assertThat(exchange.bodyRefCountAtRespond).isEqualTo(1);
        assertThat(exchange.bodySizeAtRespond).isEqualTo(
                expectedBody(HttpStatus.UNAUTHORIZED, DETAIL).getBytes(StandardCharsets.UTF_8).length);
        assertThat(allocator.buffers().getFirst().isAlive()).isTrue();
        assertThat(allocator.buffers().getFirst().refCount()).isEqualTo(1);
        assertThat(allocator.buffers().getFirst().closeCalls()).isZero();
        assertThat(allocator.finalReleases()).isZero();

        exchange.completeDeferred();

        assertThat(allocator.finalReleases()).isEqualTo(1);
        assertThat(allocator.buffers().getFirst().closeCalls()).isEqualTo(1);
        assertThat(exchange.bodyBytes).isEqualTo(
                expectedBody(HttpStatus.UNAUTHORIZED, DETAIL).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("overwriting a response body's memory does not change the next response")
    void bodiesAreNotSharedMemory() {
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange first = exchange(HttpVersion.HTTP_2, RecordingExchange.Mode.RELEASE_DEFERRED);
        send(allocator, first, HttpStatus.UNAUTHORIZED);
        MemorySegment segment = first.liveSegment();
        segment.asSlice(0, first.bodySizeAtRespond).fill((byte) 0xFF);
        first.completeDeferred();

        RecordingExchange second = exchange(HttpVersion.HTTP_1_1, RecordingExchange.Mode.RELEASE_IMMEDIATELY);
        send(allocator, second, HttpStatus.UNAUTHORIZED);

        assertThat(second.bodyBytes).isEqualTo(
                expectedBody(HttpStatus.UNAUTHORIZED, DETAIL).getBytes(StandardCharsets.UTF_8));
        assertThat(allocator.outstanding()).isZero();
    }

    @Test
    @DisplayName("with no allocator bound the answer keeps its status and headers, has no body and allocates nothing")
    void unboundAllocatorAnswersBodyless() {
        RecordingExchange exchange = exchange(HttpVersion.HTTP_2, RecordingExchange.Mode.RELEASE_IMMEDIATELY);
        MemoryStats before = base.stats();

        ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, DETAIL, CHALLENGE);

        assertThat(exchange.status).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(exchange.response.body()).isNull();
        assertThat(exchange.response.version()).isEqualTo(HttpVersion.HTTP_2);
        assertThat(exchange.header("WWW-Authenticate")).contains("Bearer");
        assertThat(exchange.header("Content-Length")).isIn(java.util.Optional.empty(),
                java.util.Optional.of("0"));
        assertThat(base.stats().allocationCount()).isEqualTo(before.allocationCount());
    }

    @Test
    @DisplayName("many responses leave no leaked and no unreleased buffer under paranoid leak detection")
    void noLeaksUnderLeakDetection() {
        MemoryStats before = base.stats();
        TrackingAllocator allocator = new TrackingAllocator(base);
        int rounds = 500;
        for (int i = 0; i < rounds; i++) {
            RecordingExchange exchange = exchange(i % 2 == 0 ? HttpVersion.HTTP_1_1 : HttpVersion.HTTP_2,
                    RecordingExchange.Mode.RELEASE_IMMEDIATELY);
            send(allocator, exchange, HttpStatus.UNAUTHORIZED);
        }
        System.gc();

        MemoryStats after = base.stats();
        assertThat(after.allocationCount() - before.allocationCount()).isEqualTo(rounds);
        assertThat(after.releaseCount() - before.releaseCount()).isEqualTo(rounds);
        assertThat(after.allocatedBytes()).isEqualTo(before.allocatedBytes());
        assertThat(after.leakCount()).isZero();
        assertThat(allocator.outstanding()).isZero();
    }

    @Test
    @DisplayName("a constant body costs no per-response allocation beyond the allocator-buffer hand-over itself")
    void noBodySizedArrayPerResponse() {
        MemoryAllocator allocator = ServiceLoader.load(MemoryProvider.class).findFirst().orElseThrow()
                .createAllocator(MemoryProviderConfig.defaults());
        try {
            byte[] constant = expectedBody(HttpStatus.UNAUTHORIZED, DETAIL).getBytes(StandardCharsets.UTF_8);
            var request = HttpRequest.noBody(HttpMethod.GET, "/me", HttpVersion.HTTP_1_1, List.of());
            HttpExchange releasing = new HttpExchange() {
                @Override
                public HttpRequest request() {
                    return request;
                }

                @Override
                public void respond(HttpResponse response) {
                    response.body().close();
                }
            };
            Runnable production = () -> ProblemResponses.send(releasing, HttpStatus.UNAUTHORIZED, DETAIL, CHALLENGE);
            Runnable reference = () -> {
                List<HttpHeader> all = new ArrayList<>(3);
                all.add(new HttpHeader("Cache-Control", "no-store"));
                all.addAll(CHALLENGE);
                all.add(0, new HttpHeader("Content-Type", "application/problem+json"));
                LoanedBuffer buffer = KernelProviders.MEMORY_ALLOCATOR.get().allocateNetwork(constant.length);
                MemorySegment.copy(constant, 0, buffer.segment(), ValueLayout.JAVA_BYTE, 0L, constant.length);
                buffer.setSize(constant.length);
                releasing.respond(new HttpResponse(HttpStatus.UNAUTHORIZED, HttpVersion.HTTP_1_1,
                        List.copyOf(all), buffer));
            };

            double produced = bytesPerCall(allocator, production);
            double referenced = bytesPerCall(allocator, reference);

            assertThat(produced - referenced)
                    .as("bytes per response above the hand-over of a precomputed body (%s vs %s)", produced, referenced)
                    .isLessThan(constant.length);
        } finally {
            allocator.close();
        }
    }

    private static final String SHORT_DETAIL = "The request lacks valid bearer credentials, so access is refused.";
    private static final String LONG_DETAIL = "The request lacks valid bearer credentials. ".repeat(90);

    /**
     * Allowed difference between the per-response heap figures of the two bodies: far below the
     * difference in body length, above the measurement noise once the path is warm.
     */
    private static final double TOLERANCE_BYTES = 8.0;

    /** The kernel's fixed cost per response plus this capability's headers, measured, with a modest margin. */
    private static final double SHORT_BODY_BOUND_BYTES = 384.0;

    private static volatile byte[] sink;

    private static Runnable productionSend(HttpExchange exchange, String detail) {
        return () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, detail, CHALLENGE);
    }

    private static HttpExchange releasingExchange() {
        var request = HttpRequest.noBody(HttpMethod.GET, "/me", HttpVersion.HTTP_1_1, List.of());
        return new HttpExchange() {
            @Override
            public HttpRequest request() {
                return request;
            }

            @Override
            public void respond(HttpResponse response) {
                response.body().close();
            }
        };
    }

    /** Median over several rounds, each after a warm-up that also fills the body cache. */
    private static double steadyBytesPerCall(MemoryAllocator allocator, Runnable call) {
        for (int i = 0; i < 300_000; i++) {
            KernelAllocators.bound(allocator, call);
        }
        double[] runs = new double[5];
        for (int i = 0; i < runs.length; i++) {
            runs[i] = bytesPerCall(allocator, call);
        }
        java.util.Arrays.sort(runs);
        return runs[runs.length / 2];
    }

    @Test
    @DisplayName("heap bytes per response do not depend on the body length")
    void heapPerResponseIsIndependentOfBodyLength() {
        MemoryAllocator allocator = ServiceLoader.load(MemoryProvider.class).findFirst().orElseThrow()
                .createAllocator(MemoryProviderConfig.defaults());
        try {
            HttpExchange releasing = releasingExchange();
            double shortBytes = steadyBytesPerCall(allocator, productionSend(releasing, SHORT_DETAIL));
            double longBytes = steadyBytesPerCall(allocator, productionSend(releasing, LONG_DETAIL));
            System.out.println("heap bytes per response: short=" + shortBytes + " long=" + longBytes
                    + " (detail lengths " + SHORT_DETAIL.length() + " / " + LONG_DETAIL.length() + ")");

            assertThat(Math.abs(longBytes - shortBytes)).as("long %s vs short %s", longBytes, shortBytes)
                    .isLessThanOrEqualTo(TOLERANCE_BYTES)
                    .isLessThan((LONG_DETAIL.length() - SHORT_DETAIL.length()) / 100.0);
            assertThat(shortBytes).as("fixed cost per response").isLessThan(SHORT_BODY_BOUND_BYTES);
        } finally {
            allocator.close();
        }
    }

    @Test
    @DisplayName("the measurement discriminates: a body-sized heap array per response breaks the same assertion")
    void controlAllocatesAndIsDetected() {
        MemoryAllocator allocator = ServiceLoader.load(MemoryProvider.class).findFirst().orElseThrow()
                .createAllocator(MemoryProviderConfig.defaults());
        try {
            double shortBytes = steadyBytesPerCall(allocator,
                    () -> sink = SHORT_DETAIL.getBytes(StandardCharsets.UTF_8).clone());
            double longBytes = steadyBytesPerCall(allocator,
                    () -> sink = LONG_DETAIL.getBytes(StandardCharsets.UTF_8).clone());
            System.out.println("control heap bytes per response: short=" + shortBytes + " long=" + longBytes);

            assertThat(Math.abs(longBytes - shortBytes)).isGreaterThan(TOLERANCE_BYTES);
        } finally {
            allocator.close();
        }
    }

    /** Smallest per-call allocation on this thread over several rounds, after warm-up. */
    private static double bytesPerCall(MemoryAllocator allocator, Runnable call) {
        var bean = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        assertThat(bean.isThreadAllocatedMemorySupported()).isTrue();
        long thread = Thread.currentThread().threadId();
        int calls = 5_000;
        double best = Double.MAX_VALUE;
        for (int round = 0; round < 6; round++) {
            long before = bean.getThreadAllocatedBytes(thread);
            for (int i = 0; i < calls; i++) {
                KernelAllocators.bound(allocator, call);
            }
            double perCall = (bean.getThreadAllocatedBytes(thread) - before) / (double) calls;
            if (round > 0) {
                best = Math.min(best, perCall);
            }
        }
        return best;
    }
}
