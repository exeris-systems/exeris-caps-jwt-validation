package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The problem body cache is bounded, never changes a response, and never hands a cached array out.
 *
 * <p>The cache size is not exposed by production code, so it is observed through its effect: a body
 * that is cached costs a small, body-length-independent amount of heap per response, while a body
 * that is not cached costs at least the encoded array. Details here are long enough that the two
 * are far apart.
 */
@DisplayName("the problem body cache is bounded and answers identically whether or not it holds a body")
class ProblemResponsesCacheTest {

    private static final List<HttpHeader> CHALLENGE = List.of(new HttpHeader("WWW-Authenticate", "Bearer"));
    private static final List<HttpStatus> STATUSES = List.of(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN,
            HttpStatus.TOO_MANY_REQUESTS, HttpStatus.SERVICE_UNAVAILABLE);
    private static final int THREADS = 16;
    private static final int DETAIL_LENGTH = 4_000;
    /** Far below the encoded length, far above a cached response's cost. */
    private static final double CACHED_COST_CEILING_BYTES = 2_000.0;

    private static MemoryAllocator base;
    /** Without leak detection, whose bookkeeping would swamp the heap figures being compared. */
    private static MemoryAllocator meter;

    @BeforeAll
    static void openAllocator() {
        base = KernelAllocators.create();
        meter = java.util.ServiceLoader.load(eu.exeris.kernel.spi.memory.MemoryProvider.class).findFirst().orElseThrow()
                .createAllocator(eu.exeris.kernel.spi.memory.MemoryProviderConfig.defaults());
    }

    @AfterAll
    static void closeAllocator() {
        base.close();
        meter.close();
        emptyCache();
    }

    @BeforeEach
    void startWithAnEmptyCache() {
        emptyCache();
    }

    /**
     * The cache is process-wide static state. These tests fill it, which would turn every other test's
     * first-seen detail into an uncached one, so each test starts and the class ends with it emptied.
     * Test-only reflection on the two fields that make up the cache.
     */
    private static void emptyCache() {
        try {
            var bodies = ProblemResponses.class.getDeclaredField("BODIES");
            bodies.setAccessible(true);
            ((java.util.Map<?, ?>) bodies.get(null)).clear();
            var count = ProblemResponses.class.getDeclaredField("CACHED");
            count.setAccessible(true);
            ((AtomicInteger) count.get(null)).set(0);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("cannot empty the problem body cache", e);
        }
    }

    private static String detail(String tag, int n) {
        String head = tag + "-" + n + "-";
        return head + "x".repeat(DETAIL_LENGTH - head.length());
    }

    private static byte[] expected(HttpStatus status, String detail) {
        return ("{\"type\":\"about:blank\",\"title\":\"" + status.reasonPhrase() + "\",\"status\":" + status.code()
                + ",\"detail\":\"" + detail + "\"}").getBytes(StandardCharsets.UTF_8);
    }

    private static HttpExchange releasing(byte[][] captured) {
        var request = HttpRequest.noBody(HttpMethod.GET, "/me", HttpVersion.HTTP_1_1, List.of());
        return new HttpExchange() {
            @Override
            public HttpRequest request() {
                return request;
            }

            @Override
            public void respond(HttpResponse response) {
                try (var body = response.body()) {
                    if (captured != null) {
                        captured[0] = body.segment().asSlice(0, body.size())
                                .toArray(java.lang.foreign.ValueLayout.JAVA_BYTE);
                    }
                }
            }
        };
    }

    private static byte[] bytesOf(HttpStatus status, String detail) {
        byte[][] captured = new byte[1][];
        HttpExchange exchange = releasing(captured);
        KernelAllocators.bound(base, () -> ProblemResponses.send(exchange, status, detail, CHALLENGE));
        return captured[0];
    }

    private static void sendOnly(HttpExchange exchange, HttpStatus status, String detail) {
        KernelAllocators.bound(base, () -> ProblemResponses.send(exchange, status, detail, CHALLENGE));
    }

    /** Heap bytes per call on this thread for one status and detail, after a short warm-up. */
    private static double heapPerResponse(HttpStatus status, String detail) {
        var bean = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        long thread = Thread.currentThread().threadId();
        HttpExchange exchange = releasing(null);
        for (int i = 0; i < 5; i++) {
            KernelAllocators.bound(meter, () -> ProblemResponses.send(exchange, status, detail, CHALLENGE));
        }
        int calls = 20;
        long before = bean.getThreadAllocatedBytes(thread);
        for (int i = 0; i < calls; i++) {
            KernelAllocators.bound(meter, () -> ProblemResponses.send(exchange, status, detail, CHALLENGE));
        }
        return (bean.getThreadAllocatedBytes(thread) - before) / (double) calls;
    }

    private static boolean looksCached(HttpStatus status, String detail) {
        return heapPerResponse(status, detail) < CACHED_COST_CEILING_BYTES;
    }

    /** Sends well over the bound of distinct (status, detail) pairs from one thread. */
    private static void overfill(String tag) {
        HttpExchange exchange = releasing(null);
        for (int i = 0; i < ProblemResponses.MAX_CACHED_BODIES * 3; i++) {
            sendOnly(exchange, STATUSES.get(i % STATUSES.size()), detail(tag, i));
        }
    }

    @Test
    @DisplayName("the bound is a positive constant")
    void boundIsNamed() {
        assertThat(ProblemResponses.MAX_CACHED_BODIES).isPositive();
    }

    @Test
    @DisplayName("many threads sending distinct details finish in time, answer correctly, and leave at most bound + threads cached")
    void concurrentDistinctDetailsStayBounded() throws Exception {
        int perThread = ProblemResponses.MAX_CACHED_BODIES * 4;
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger wrong = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < THREADS; t++) {
            int thread = t;
            futures.add(pool.submit(() -> {
                start.await();
                byte[][] captured = new byte[1][];
                HttpExchange exchange = releasing(captured);
                for (int i = 0; i < perThread; i++) {
                    HttpStatus status = STATUSES.get((thread + i) % STATUSES.size());
                    String detail = detail("storm", thread * perThread + i);
                    sendOnly(exchange, status, detail);
                    if (!java.util.Arrays.equals(captured[0], expected(status, detail))) {
                        wrong.incrementAndGet();
                    }
                }
                return null;
            }));
        }
        start.countDown();
        pool.shutdown();
        boolean finished = pool.awaitTermination(120, TimeUnit.SECONDS);
        if (!finished) {
            pool.shutdownNow();
        }
        assertThat(finished).as("all senders completed (no deadlock)").isTrue();
        for (Future<?> f : futures) {
            f.get(1, TimeUnit.SECONDS);
        }
        assertThat(wrong.get()).as("responses with wrong bytes").isZero();

        int cached = 0;
        for (int t = 0; t < THREADS; t++) {
            for (int i = 0; i < perThread; i++) {
                HttpStatus status = STATUSES.get((t + i) % STATUSES.size());
                if (looksCached(status, detail("storm", t * perThread + i))) {
                    cached++;
                }
            }
        }
        assertThat(cached).as("cached bodies among the %d pairs sent", THREADS * perThread)
                .isLessThanOrEqualTo(ProblemResponses.MAX_CACHED_BODIES + THREADS)
                .as("the cache did fill: the observation can see cached bodies")
                .isGreaterThanOrEqualTo(ProblemResponses.MAX_CACHED_BODIES / 2);
    }

    @Test
    @DisplayName("once the cache is full, a first-seen detail answers with exactly the bytes a cached one would")
    void firstSeenWhenFullHasTheSameBytes() {
        overfill("fill");
        String fresh = detail("late", 1);

        for (HttpStatus status : STATUSES) {
            byte[] first = bytesOf(status, fresh);
            byte[] second = bytesOf(status, fresh);
            assertThat(first).isEqualTo(expected(status, fresh));
            assertThat(second).isEqualTo(first);
        }
    }

    @Test
    @DisplayName("a full cache does not grow: a detail first seen when full stays uncached across repeated sends")
    void fullCacheDoesNotGrow() {
        overfill("grow");
        String fresh = detail("never-stored", 1);
        bytesOf(HttpStatus.UNAUTHORIZED, fresh);
        // Single-threaded, so the count is exactly at the bound: a further insert is refused.
        for (int i = 0; i < 50; i++) {
            bytesOf(HttpStatus.UNAUTHORIZED, fresh);
        }

        assertThat(looksCached(HttpStatus.UNAUTHORIZED, fresh)).isFalse();
    }

    @Test
    @DisplayName("the bytes for a detail are unchanged after other details were added, and a cached one is not evicted")
    void cachedBytesStableAfterOtherDetails() {
        String subject = detail("subject", 1);
        byte[] before = bytesOf(HttpStatus.FORBIDDEN, subject);
        assertThat(looksCached(HttpStatus.FORBIDDEN, subject)).as("cached while there is room").isTrue();

        overfill("others");

        assertThat(bytesOf(HttpStatus.FORBIDDEN, subject)).isEqualTo(before)
                .isEqualTo(expected(HttpStatus.FORBIDDEN, subject));
        assertThat(looksCached(HttpStatus.FORBIDDEN, subject)).as("a cached body is never evicted").isTrue();
    }

    @Test
    @DisplayName("the same detail under different statuses gets each status's own body")
    void statusIsPartOfTheKey() {
        String shared = detail("shared", 1);
        for (HttpStatus status : STATUSES) {
            assertThat(bytesOf(status, shared)).isEqualTo(expected(status, shared));
        }
        for (HttpStatus status : STATUSES) {
            assertThat(bytesOf(status, shared)).isEqualTo(expected(status, shared));
        }
    }

    @Test
    @DisplayName("each response owns its kernel buffer: overwriting one never changes a live or later response")
    void bufferIsNotTheCachedArray() {
        String subject = detail("owned", 1);
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange first = new RecordingExchange(HttpMethod.GET, "/me", List.of(), HttpVersion.HTTP_2,
                RecordingExchange.Mode.RELEASE_DEFERRED);
        RecordingExchange second = new RecordingExchange(HttpMethod.GET, "/me", List.of(), HttpVersion.HTTP_2,
                RecordingExchange.Mode.RELEASE_DEFERRED);
        KernelAllocators.bound(allocator,
                () -> ProblemResponses.send(first, HttpStatus.UNAUTHORIZED, subject, CHALLENGE));
        KernelAllocators.bound(allocator,
                () -> ProblemResponses.send(second, HttpStatus.UNAUTHORIZED, subject, CHALLENGE));

        MemorySegment a = first.liveSegment();
        MemorySegment b = second.liveSegment();
        assertThat(a.address()).isNotEqualTo(b.address());
        assertThat(a.isNative()).isTrue();
        a.asSlice(0, first.bodySizeAtRespond).fill((byte) 0x7F);
        first.completeDeferred();
        second.completeDeferred();

        assertThat(second.bodyBytes).isEqualTo(expected(HttpStatus.UNAUTHORIZED, subject));
        assertThat(bytesOf(HttpStatus.UNAUTHORIZED, subject)).isEqualTo(expected(HttpStatus.UNAUTHORIZED, subject));
        assertThat(allocator.outstanding()).isZero();
    }

    @Test
    @DisplayName("a body built because the cache is full is also copied into its own kernel buffer")
    void uncachedBodyIsCopiedToo() {
        overfill("own");
        String subject = detail("own-late", 1);
        TrackingAllocator allocator = new TrackingAllocator(base);
        RecordingExchange first = new RecordingExchange(HttpMethod.GET, "/me", List.of(), HttpVersion.HTTP_2,
                RecordingExchange.Mode.RELEASE_DEFERRED);
        KernelAllocators.bound(allocator,
                () -> ProblemResponses.send(first, HttpStatus.UNAUTHORIZED, subject, CHALLENGE));

        assertThat(first.response.body()).isSameAs(allocator.buffers().getFirst());
        first.liveSegment().asSlice(0, first.bodySizeAtRespond).fill((byte) 0x7F);
        first.completeDeferred();

        assertThat(bytesOf(HttpStatus.UNAUTHORIZED, subject)).isEqualTo(expected(HttpStatus.UNAUTHORIZED, subject));
    }
}
