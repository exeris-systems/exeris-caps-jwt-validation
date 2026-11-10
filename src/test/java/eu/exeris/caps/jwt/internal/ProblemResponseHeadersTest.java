package eu.exeris.caps.jwt.internal;

import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("headers that depend only on build-time values are built once, shared and immutable")
class ProblemResponseHeadersTest {

    private static final String DETAIL = "The request lacks valid bearer credentials.";
    private static final HttpHeader CONTENT_TYPE = new HttpHeader("Content-Type", "application/problem+json");
    private static final HttpHeader NO_STORE = new HttpHeader("Cache-Control", "no-store");
    private static final HttpHeader BEARER = new HttpHeader("WWW-Authenticate", "Bearer");
    private static final HttpHeader INVALID = new HttpHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
    private static final HttpHeader RETRY = new HttpHeader("Retry-After", "30");

    private static MemoryAllocator base;

    @BeforeAll
    static void openAllocator() {
        base = KernelAllocators.create();
    }

    @AfterAll
    static void closeAllocator() {
        base.close();
    }

    private static RecordingExchange exchange() {
        return new RecordingExchange(HttpMethod.GET, "/me", List.of(), HttpVersion.HTTP_1_1,
                RecordingExchange.Mode.RELEASE_IMMEDIATELY);
    }

    private static RecordingExchange sendShared(ProblemResponses.Headers headers, boolean bound) {
        RecordingExchange exchange = exchange();
        TrackingAllocator allocator = new TrackingAllocator(base);
        Runnable send = () -> ProblemResponses.send(exchange, HttpStatus.UNAUTHORIZED, DETAIL, headers);
        if (bound) {
            KernelAllocators.bound(allocator, send);
        } else {
            send.run();
        }
        return exchange;
    }

    @Test
    @DisplayName("with a body: Content-Type, Cache-Control, then the additional headers in order")
    void withBodyOrder() {
        ProblemResponses.Headers headers = ProblemResponses.Headers.of(List.of(BEARER, RETRY));

        assertThat(headers.withBody()).containsExactly(CONTENT_TYPE, NO_STORE, BEARER, RETRY);
        assertThat(sendShared(headers, true).response.headers()).containsExactly(CONTENT_TYPE, NO_STORE, BEARER, RETRY);
    }

    @Test
    @DisplayName("without a body: Cache-Control, then the additional headers in order, and no Content-Type")
    void withoutBodyOrder() {
        ProblemResponses.Headers headers = ProblemResponses.Headers.of(List.of(BEARER, RETRY));

        assertThat(headers.withoutBody()).containsExactly(NO_STORE, BEARER, RETRY);
        RecordingExchange exchange = sendShared(headers, false);
        assertThat(exchange.response.headers()).containsExactly(NO_STORE, BEARER, RETRY);
        assertThat(exchange.response.body()).isNull();
    }

    @Test
    @DisplayName("an empty additional list yields only the fixed headers")
    void noAdditionalHeaders() {
        ProblemResponses.Headers headers = ProblemResponses.Headers.of(List.of());

        assertThat(headers.withBody()).containsExactly(CONTENT_TYPE, NO_STORE);
        assertThat(headers.withoutBody()).containsExactly(NO_STORE);
    }

    @Test
    @DisplayName("the shared headers equal the list overload's headers, name, value and order")
    void sameAsListOverload() {
        for (HttpHeader challenge : List.of(BEARER, INVALID)) {
            ProblemResponses.Headers shared = ProblemResponses.Headers.of(List.of(challenge));
            RecordingExchange viaList = exchange();
            KernelAllocators.bound(new TrackingAllocator(base),
                    () -> ProblemResponses.send(viaList, HttpStatus.UNAUTHORIZED, DETAIL, List.of(challenge)));

            assertThat(sendShared(shared, true).response.headers()).isEqualTo(viaList.response.headers());
            assertThat(viaList.response.headers()).containsExactly(CONTENT_TYPE, NO_STORE, challenge);
        }
    }

    @Test
    @DisplayName("responses of the same kind reuse the one immutable list instance")
    void sameInstanceReused() {
        ProblemResponses.Headers headers = ProblemResponses.Headers.of(List.of(BEARER));

        RecordingExchange a = sendShared(headers, true);
        RecordingExchange b = sendShared(headers, true);
        assertThat(a.response.headers()).isSameAs(headers.withBody()).isSameAs(b.response.headers());

        RecordingExchange c = sendShared(headers, false);
        RecordingExchange d = sendShared(headers, false);
        assertThat(c.response.headers()).isSameAs(headers.withoutBody()).isSameAs(d.response.headers());
    }

    @Test
    @DisplayName("the shared lists cannot be modified, and later changes to the input do not reach them")
    void immutableAndDetached() {
        List<HttpHeader> input = new ArrayList<>(List.of(BEARER));
        ProblemResponses.Headers headers = ProblemResponses.Headers.of(input);
        input.add(RETRY);
        input.set(0, INVALID);

        assertThat(headers.withBody()).containsExactly(CONTENT_TYPE, NO_STORE, BEARER);
        assertThat(headers.withoutBody()).containsExactly(NO_STORE, BEARER);
        assertThatThrownBy(() -> headers.withBody().add(RETRY)).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> headers.withoutBody().set(0, RETRY)).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> headers.withBody().clear()).isInstanceOf(UnsupportedOperationException.class);
    }
}
