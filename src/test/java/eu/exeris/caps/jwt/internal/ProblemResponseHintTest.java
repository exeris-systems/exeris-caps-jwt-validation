package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.memory.AllocationHint;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("a problem body is allocated by hint, sized to its length, and never relies on buffer contents")
class ProblemResponseHintTest {

    private static final List<HttpHeader> CHALLENGE = List.of(new HttpHeader("WWW-Authenticate", "Bearer"));
    private static final int JUMBO_BYTES = AllocationHint.JUMBO.sizeBytes();

    private static MemoryAllocator base;

    @BeforeAll
    static void openAllocator() {
        base = KernelAllocators.create();
    }

    @AfterAll
    static void closeAllocator() {
        base.close();
    }

    /** Length of the encoded body when the detail is empty. */
    private static int fixedLength() {
        return encoded(HttpStatus.UNAUTHORIZED, "").length;
    }

    private static byte[] encoded(HttpStatus status, String detail) {
        return ("{\"type\":\"about:blank\",\"title\":\"" + status.reasonPhrase() + "\",\"status\":" + status.code()
                + ",\"detail\":\"" + detail + "\"}").getBytes(StandardCharsets.UTF_8);
    }

    /** A detail text that makes the encoded body exactly {@code bodyLength} bytes long. */
    private static String detailForBody(int bodyLength) {
        return "a".repeat(bodyLength - fixedLength());
    }

    private static RecordingExchange exchange(RecordingExchange.Mode mode) {
        return new RecordingExchange(HttpMethod.GET, "/me", List.of(), HttpVersion.HTTP_1_1, mode);
    }

    // ---- hintFor: the pure choice ----

    @Test
    @DisplayName("hintFor returns the smallest of MICRO..JUMBO that holds the length, at every boundary")
    void hintBoundaries() {
        Map<Integer, AllocationHint> expected = new LinkedHashMap<>();
        expected.put(0, AllocationHint.MICRO);
        expected.put(1, AllocationHint.MICRO);
        expected.put(511, AllocationHint.MICRO);
        expected.put(512, AllocationHint.MICRO);
        expected.put(513, AllocationHint.SMALL);
        expected.put(4_096, AllocationHint.SMALL);
        expected.put(4_097, AllocationHint.MEDIUM);
        expected.put(16_384, AllocationHint.MEDIUM);
        expected.put(16_385, AllocationHint.STREAMING_CHUNK);
        expected.put(32_768, AllocationHint.STREAMING_CHUNK);
        expected.put(32_769, AllocationHint.NETWORK_FRAME);
        expected.put(65_536, AllocationHint.NETWORK_FRAME);
        expected.put(65_537, AllocationHint.JUMBO);
        expected.put(131_072, AllocationHint.JUMBO);

        expected.forEach((length, hint) -> assertThat(ProblemResponses.hintFor(length))
                .as("hint for %s bytes", length).isEqualTo(hint));
    }

    @Test
    @DisplayName("hintFor agrees with the enum on every length around every boundary, and is never SESSION")
    void hintAgreesWithEnum() {
        for (AllocationHint hint : AllocationHint.values()) {
            for (int length = Math.max(0, hint.sizeBytes() - 2); length <= hint.sizeBytes() + 2
                    && length <= JUMBO_BYTES; length++) {
                AllocationHint chosen = ProblemResponses.hintFor(length);
                assertThat(chosen).as("hint for %s", length).isEqualTo(ProblemResponsesTest.smallestHintHolding(length));
                assertThat(chosen).isNotEqualTo(AllocationHint.SESSION);
                assertThat(chosen.sizeBytes()).isGreaterThanOrEqualTo(length);
            }
        }
    }

    @Test
    @DisplayName("hintFor refuses a negative length and a length above the largest hint, never truncating")
    void hintRefusesOutOfRange() {
        for (int length : new int[] {-1, Integer.MIN_VALUE, JUMBO_BYTES + 1, 1 << 20, Integer.MAX_VALUE}) {
            assertThatThrownBy(() -> ProblemResponses.hintFor(length))
                    .as("length %s", length).isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ---- send: allocation by hint ----

    @Test
    @DisplayName("each boundary length is allocated under its hint, sized to the body, with the exact bytes and one release")
    void boundaryBodiesEndToEnd() {
        int[] lengths = {fixedLength(), 512, 513, 4_096, 4_097, 16_384, 16_385, 32_768, 32_769, 65_536, 65_537,
            JUMBO_BYTES};
        for (int length : lengths) {
            TrackingAllocator allocator = TrackingAllocator.withDirtyBuffers(base);
            RecordingExchange exchange = exchange(RecordingExchange.Mode.RELEASE_IMMEDIATELY);
            String detail = detailForBody(length);

            KernelAllocators.bound(allocator,
                    () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, detail, CHALLENGE));

            AllocationHint hint = ProblemResponsesTest.smallestHintHolding(length);
            assertThat(allocator.hints()).as("hints for %s", length).containsExactly(hint);
            assertThat(allocator.networkCalls()).isZero();
            assertThat(allocator.allocations()).isEqualTo(1);
            assertThat(exchange.bodySizeAtRespond).as("size for %s", length).isEqualTo(length);
            assertThat(exchange.bodyCapacityAtRespond).isEqualTo((long) hint.sizeBytes());
            assertThat(exchange.bodyBytes).as("bytes for %s", length)
                    .isEqualTo(encoded(HttpStatus.UNAUTHORIZED, detail));
            assertThat(allocator.finalReleases()).isEqualTo(1);
            assertThat(allocator.buffers().getFirst().closeCalls()).isEqualTo(1);
        }
    }

    @Test
    @DisplayName("the bytes sent are the body alone when the rest of the buffer holds a non-zero pattern")
    void remainderOfTheBufferIsNotRelied() {
        for (HttpStatus status : List.of(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN, HttpStatus.TOO_MANY_REQUESTS,
                HttpStatus.SERVICE_UNAVAILABLE)) {
            TrackingAllocator allocator = TrackingAllocator.withDirtyBuffers(base);
            RecordingExchange exchange = exchange(RecordingExchange.Mode.RELEASE_DEFERRED);

            KernelAllocators.bound(allocator,
                    () -> ProblemResponses.send(exchange, status, "Fixed text.", CHALLENGE));

            byte[] expected = encoded(status, "Fixed text.");
            assertThat(exchange.bodySizeAtRespond).isEqualTo(expected.length);
            assertThat(exchange.bodyCapacityAtRespond).isGreaterThan(expected.length);
            exchange.completeDeferred();
            assertThat(exchange.bodyBytes).isEqualTo(expected);
            assertThat(exchange.bodyBytes).doesNotContain(TrackingAllocator.DIRTY);
            assertThat(allocator.outstanding()).isZero();
        }
    }

    @Test
    @DisplayName("the overload with shared headers allocates by hint as well")
    void sharedHeadersOverload() {
        TrackingAllocator allocator = TrackingAllocator.withDirtyBuffers(base);
        RecordingExchange exchange = exchange(RecordingExchange.Mode.RELEASE_IMMEDIATELY);
        String detail = detailForBody(513);

        KernelAllocators.bound(allocator, () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, detail,
                ProblemResponses.Headers.of(CHALLENGE)));

        assertThat(allocator.hints()).containsExactly(AllocationHint.SMALL);
        assertThat(allocator.networkCalls()).isZero();
        assertThat(exchange.bodySizeAtRespond).isEqualTo(513L);
        assertThat(exchange.bodyBytes).isEqualTo(encoded(HttpStatus.UNAUTHORIZED, detail));
        assertThat(allocator.outstanding()).isZero();
    }

    // ---- bodies larger than the largest hint ----

    @Test
    @DisplayName("a body one byte over the largest hint is refused before any allocation or hand-over")
    void oversizeBodyFailsClosed() {
        for (int length : new int[] {JUMBO_BYTES + 1, 1 << 20}) {
            TrackingAllocator allocator = TrackingAllocator.withDirtyBuffers(base);
            RecordingExchange exchange = exchange(RecordingExchange.Mode.RELEASE_IMMEDIATELY);
            String detail = detailForBody(length);

            assertThatThrownBy(() -> KernelAllocators.bound(allocator,
                    () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, detail, CHALLENGE)))
                    .as("length %s", length).isInstanceOf(IllegalArgumentException.class);

            assertThat(allocator.allocations()).isZero();
            assertThat(allocator.networkCalls()).isZero();
            assertThat(allocator.finalReleases()).isZero();
            assertThat(exchange.respondCalls()).isZero();
        }
    }

    // ---- failure paths under hint allocation ----

    @Test
    @DisplayName("a closed allocator's failure reaches the caller and nothing is handed over")
    void allocationFailureReachesTheCaller() {
        MemoryAllocator closed = KernelAllocators.create();
        closed.close();
        RecordingExchange exchange = exchange(RecordingExchange.Mode.RELEASE_IMMEDIATELY);

        assertThatThrownBy(() -> KernelAllocators.bound(closed,
                () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, "Fixed text.", CHALLENGE)))
                .isInstanceOf(IllegalStateException.class);

        assertThat(exchange.respondCalls()).isZero();
    }

    @Test
    @DisplayName("on each failure path the hint-sized buffer is released exactly once")
    void releaseCountsOnFailurePaths() {
        record Case(String name, TrackingAllocator allocator, RecordingExchange.Mode mode, int respondCalls) {
        }
        List<Case> cases = List.of(
                new Case("reject", TrackingAllocator.withDirtyBuffers(base),
                        RecordingExchange.Mode.REJECT_BEFORE_TAKE, 1),
                new Case("short capacity", TrackingAllocator.withShortCapacity(base),
                        RecordingExchange.Mode.RELEASE_IMMEDIATELY, 0),
                new Case("setSize fails", TrackingAllocator.withFailingSetSize(base),
                        RecordingExchange.Mode.RELEASE_IMMEDIATELY, 0));
        for (Case c : cases) {
            RecordingExchange exchange = exchange(c.mode());

            assertThatThrownBy(() -> KernelAllocators.bound(c.allocator(),
                    () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, "Fixed text.", CHALLENGE)))
                    .as(c.name()).isInstanceOf(IllegalStateException.class);

            assertThat(exchange.respondCalls()).as(c.name()).isEqualTo(c.respondCalls());
            assertThat(c.allocator().hints()).as(c.name()).containsExactly(AllocationHint.MICRO);
            assertThat(c.allocator().networkCalls()).isZero();
            assertThat(c.allocator().finalReleases()).as(c.name()).isEqualTo(1);
            assertThat(c.allocator().buffers().getFirst().closeCalls()).as(c.name()).isEqualTo(1);
        }
    }
}
