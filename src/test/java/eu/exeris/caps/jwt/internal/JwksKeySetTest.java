package eu.exeris.caps.jwt.internal;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

@DisplayName("JwksKeySet")
class JwksKeySetTest {

    private static final long SECOND = 1_000_000_000L;
    private static final KeyPair ED_1 = TestTokens.ed25519();
    private static final KeyPair ED_2 = TestTokens.ed25519();
    private static final long MS = 1_000_000L;

    private final List<JwksKeySet> started = new ArrayList<>();

    @AfterEach
    void stopAll() {
        started.forEach(JwksKeySet::stop);
    }

    private JwksKeySet begin(JwksKeySet keySet) {
        started.add(keySet);
        keySet.start(5 * SECOND);
        return keySet;
    }

    private static void await(java.util.function.BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + 5 * SECOND;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition not reached within 5 s");
            }
            Thread.sleep(2);
        }
    }

    private static String one() {
        return TestTokens.jwks(TestTokens.okpJwk("k1", ED_1));
    }

    @Test
    @DisplayName("binds each key to the algorithm its JWK implies and skips what it cannot bind")
    void parsesSupportedKeysOnly() {
        String jwks = TestTokens.jwks(
                TestTokens.okpJwk("ed", ED_1),
                TestTokens.rsaJwk("rsa", TestTokens.rsa(2048)),
                TestTokens.rsaJwk("rsa-small", TestTokens.rsa(1024)),
                TestTokens.okpJwk("mislabelled", ED_2).replace("\"alg\":\"EdDSA\"", "\"alg\":\"RS256\""),
                "{\"kty\":\"oct\",\"kid\":\"hmac\",\"k\":\"c2VjcmV0\"}",
                TestTokens.okpJwk("enc", ED_2).replace("\"use\":\"sig\"", "\"use\":\"enc\""));

        var keys = JwksKeySet.parse(jwks);

        assertThat(keys).containsOnlyKeys("ed", "rsa");
        assertThat(keys.get("ed").algorithm()).isEqualTo(JwksKeySet.EDDSA);
        assertThat(keys.get("rsa").algorithm()).isEqualTo(JwksKeySet.RS256);
    }

    @Test
    @DisplayName("a kid published twice is trusted in neither copy")
    void duplicateKidDropped() {
        var keys = JwksKeySet.parse(TestTokens.jwks(TestTokens.okpJwk("k", ED_1), TestTokens.okpJwk("k", ED_2)));
        assertThat(keys).isEmpty();
    }

    @Test
    @DisplayName("before the first load every kid is refused and the source has not been called")
    void findBeforeFirstLoadRefuses() {
        AtomicInteger calls = new AtomicInteger();
        JwksKeySet keySet = JwksKeySet.fromSource(() -> {
            calls.incrementAndGet();
            return one();
        }, 300 * SECOND, 30 * SECOND, () -> 0);

        assertThat(keySet.find("k1")).isEmpty();
        assertThat(keySet.find("other")).isEmpty();
        assertThat(calls).hasValue(0);
    }

    @Test
    @DisplayName("the refresher is reachable for a wake-up from its first fetch on")
    void refresherIsPublishedBeforeItRuns() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        AtomicReference<JwksKeySet> holder = new AtomicReference<>();
        AtomicBoolean publishedDuringFirstFetch = new AtomicBoolean();
        CountDownLatch assigned = new CountDownLatch(1);
        JwksKeySet keySet = JwksKeySet.fromSource(() -> {
            try {
                assigned.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            publishedDuringFirstFetch.compareAndSet(false, holder.get().isRefresherAlive());
            return one();
        }, 300 * SECOND, 30 * SECOND, 600 * SECOND, clock::get);
        holder.set(keySet);
        assigned.countDown();
        begin(keySet);

        assertThat(keySet.find("k1")).isPresent();
        assertThat(publishedDuringFirstFetch).isTrue();
    }

    @Test
    @DisplayName("the source is only ever called on the named virtual refresher thread")
    void findNeverCallsSourceOnTheCallingThread() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        AtomicInteger fetches = new AtomicInteger();
        AtomicBoolean calledOnTestThread = new AtomicBoolean();
        List<Thread> callers = new CopyOnWriteArrayList<>();
        Thread testThread = Thread.currentThread();
        JwksKeySet keySet = begin(JwksKeySet.fromSource(() -> {
            fetches.incrementAndGet();
            callers.add(Thread.currentThread());
            if (Thread.currentThread() == testThread) {
                calledOnTestThread.set(true);
            }
            return one();
        }, 300 * SECOND, 30 * SECOND, 600 * SECOND, clock::get));

        assertThat(keySet.find("k1")).isPresent();
        for (int i = 0; i < 20; i++) {
            keySet.find("unknown-" + i);
        }
        clock.addAndGet(31 * SECOND);
        keySet.wake();
        await(() -> fetches.get() >= 2);
        clock.addAndGet(400 * SECOND);
        keySet.wake();
        await(() -> fetches.get() >= 3);
        keySet.find("k1");

        assertThat(calledOnTestThread).isFalse();
        assertThat(callers).isNotEmpty().allSatisfy(t -> {
            assertThat(t.isVirtual()).isTrue();
            assertThat(t.getName()).isEqualTo("exeris-jwt-jwks-refresh");
        });
    }

    @Test
    @DisplayName("any number of unknown kids request at most one reload per minimum refresh interval")
    void unknownKidRequestsAtMostOneRefreshPerWindow() throws Exception {
        AtomicLong clock = new AtomicLong(100 * SECOND);
        AtomicInteger fetches = new AtomicInteger();
        AtomicReference<String> published = new AtomicReference<>(one());
        JwksKeySet keySet = begin(JwksKeySet.fromSource(() -> {
            fetches.incrementAndGet();
            return published.get();
        }, 300 * SECOND, 30 * SECOND, clock::get));
        long t0 = clock.get();
        assertThat(fetches).hasValue(1);
        assertThat(keySet.nanosUntilDue(t0)).isEqualTo(300 * SECOND);

        for (int i = 0; i < 1000; i++) {
            assertThat(keySet.find("invented-" + i)).isEmpty();
        }
        assertThat(keySet.nanosUntilDue(t0 + 30 * SECOND - 1)).isPositive();
        assertThat(keySet.nanosUntilDue(t0 + 30 * SECOND)).isLessThanOrEqualTo(0);
        keySet.wake();
        Thread.sleep(50);
        assertThat(fetches).as("the clock has not reached the window").hasValue(1);

        published.set(TestTokens.jwks(TestTokens.okpJwk("k1", ED_1), TestTokens.okpJwk("k2", ED_2)));
        clock.addAndGet(30 * SECOND);
        keySet.wake();
        await(() -> fetches.get() == 2);
        await(() -> keySet.find("k2").isPresent());
        Thread.sleep(50);
        assertThat(fetches).hasValue(2);
    }

    @Test
    @DisplayName("failed reloads keep the keys until the maximum staleness, then every key is refused until recovery")
    void staleKeysAreRefused() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        AtomicInteger fetches = new AtomicInteger();
        AtomicBoolean failing = new AtomicBoolean();
        JwksKeySet keySet = begin(JwksKeySet.fromSource(() -> {
            fetches.incrementAndGet();
            if (failing.get()) {
                throw new IllegalStateException("endpoint down");
            }
            return one();
        }, 300 * SECOND, 30 * SECOND, 600 * SECOND, clock::get));
        assertThat(keySet.find("k1")).isPresent();

        failing.set(true);
        clock.set(301 * SECOND);
        keySet.wake();
        await(() -> fetches.get() == 2);
        assertThat(keySet.find("k1")).isPresent();

        clock.set(599 * SECOND);
        assertThat(keySet.find("k1")).isPresent();
        clock.set(600 * SECOND);
        assertThat(keySet.find("k1")).isEmpty();

        failing.set(false);
        clock.set(700 * SECOND);
        keySet.wake();
        await(() -> fetches.get() >= 3);
        await(() -> keySet.find("k1").isPresent());
    }

    @Test
    @DisplayName("after a failed attempt the next one is due after the minimum interval, not the refresh interval")
    void failedAttemptRetriesAfterMinInterval() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        AtomicInteger fetches = new AtomicInteger();
        AtomicBoolean failing = new AtomicBoolean();
        JwksKeySet keySet = begin(JwksKeySet.fromSource(() -> {
            fetches.incrementAndGet();
            if (failing.get()) {
                throw new IllegalStateException("endpoint down");
            }
            return one();
        }, 300 * SECOND, 30 * SECOND, 600 * SECOND, clock::get));
        failing.set(true);
        clock.set(300 * SECOND);
        keySet.wake();
        await(() -> fetches.get() == 2);

        assertThat(keySet.nanosUntilDue(300 * SECOND)).isEqualTo(30 * SECOND);
    }

    @Test
    @DisplayName("the periodic reload picks up a rotated key")
    void periodicRefreshPicksUpRotatedKey() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        AtomicInteger fetches = new AtomicInteger();
        AtomicReference<String> published = new AtomicReference<>(one());
        JwksKeySet keySet = begin(JwksKeySet.fromSource(() -> {
            fetches.incrementAndGet();
            return published.get();
        }, 300 * SECOND, 30 * SECOND, 600 * SECOND, clock::get));
        published.set(TestTokens.jwks(TestTokens.okpJwk("k2", ED_2)));

        clock.set(300 * SECOND);
        keySet.wake();
        await(() -> fetches.get() == 2);
        await(() -> keySet.find("k2").isPresent());
        assertThat(keySet.find("k1")).isEmpty();
    }

    @Test
    @DisplayName("stop ends the refresher, is idempotent, and start after stop does nothing")
    void stopEndsTheRefresher() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        AtomicInteger fetches = new AtomicInteger();
        JwksKeySet keySet = begin(JwksKeySet.fromSource(() -> {
            fetches.incrementAndGet();
            return one();
        }, 300 * SECOND, 30 * SECOND, 600 * SECOND, clock::get));
        assertThat(keySet.isRefresherAlive()).isTrue();

        keySet.stop();
        keySet.stop();

        assertThat(keySet.isRefresherAlive()).isFalse();
        assertThat(keySet.find("k1")).as("snapshot serves until staleness").isPresent();
        keySet.start(SECOND);
        assertThat(fetches).hasValue(1);
        assertThat(keySet.isRefresherAlive()).isFalse();
    }

    @Test
    @DisplayName("stop interrupts a fetch in flight and returns within its bound")
    void stopInterruptsABlockedFetch() throws Exception {
        AtomicLong clock = new AtomicLong(0);
        CountDownLatch inFetch = new CountDownLatch(1);
        AtomicInteger fetches = new AtomicInteger();
        JwksKeySet keySet = JwksKeySet.fromSource(() -> {
            if (fetches.incrementAndGet() == 1) {
                return one();
            }
            inFetch.countDown();
            try {
                new CountDownLatch(1).await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted", e);
            }
            return one();
        }, 300 * SECOND, 30 * SECOND, 600 * SECOND, clock::get);
        keySet.start(SECOND);
        clock.set(300 * SECOND);
        keySet.wake();
        assertThat(inFetch.await(5, TimeUnit.SECONDS)).isTrue();

        assertTimeoutPreemptively(java.time.Duration.ofSeconds(4), keySet::stop);

        assertThat(keySet.isRefresherAlive()).isFalse();
    }

    @Test
    @DisplayName("start waits for the first attempt only up to its bound; the key set serves once the load lands")
    void startWaitsForTheFirstAttemptBounded() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        JwksKeySet keySet = JwksKeySet.fromSource(() -> {
            try {
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return one();
        }, 300 * SECOND, 30 * SECOND, 600 * SECOND, System::nanoTime);
        started.add(keySet);

        long before = System.nanoTime();
        keySet.start(100 * MS);
        long waited = System.nanoTime() - before;

        assertThat(waited).isBetween(90 * MS, 3 * SECOND);
        assertThat(keySet.find("k1")).isEmpty();
        release.countDown();
        await(() -> keySet.find("k1").isPresent());
    }

    @Test
    @DisplayName("the default maximum staleness is one day or twice the refresh interval, capped at seven days")
    void defaultMaxStalenessIsOneDayOrTwiceRefresh() {
        long day = 86_400L * SECOND;
        assertThat(JwksKeySet.defaultMaxStalenessNanos(300 * SECOND)).isEqualTo(day);
        assertThat(JwksKeySet.defaultMaxStalenessNanos(day)).isEqualTo(2 * day);
        assertThat(JwksKeySet.defaultMaxStalenessNanos(4 * day)).isEqualTo(7 * day);
        assertThat(JwksKeySet.defaultMaxStalenessNanos(Long.MAX_VALUE)).isEqualTo(7 * day);
    }

    @Test
    @DisplayName("a fixed key set has no refresher")
    void fixedKeySetHasNoRefresher() {
        JwksKeySet keySet = JwksKeySet.fixed(List.of(JwksKeySet.bind("k1", ED_1.getPublic())));
        keySet.start(SECOND);

        assertThat(keySet.isRefresherAlive()).isFalse();
        assertThat(keySet.find("k1")).isPresent();
        assertThat(keySet.find("nope")).isEmpty();
        keySet.stop();
    }

    @Test
    @DisplayName("a lookup allocates no more than its Optional, and an unknown kid with a reload already requested allocates nothing")
    void findAllocatesNoMoreThanTheOptional() {
        var bean = (com.sun.management.ThreadMXBean) java.lang.management.ManagementFactory.getThreadMXBean();
        AtomicLong clock = new AtomicLong(0);
        JwksKeySet keySet = begin(JwksKeySet.fromSource(JwksKeySetTest::one, 300 * SECOND, 30 * SECOND,
                600 * SECOND, clock::get));
        for (int i = 0; i < 10_000; i++) {
            keySet.find("k1");
            keySet.find("unknown");
        }
        long id = Thread.currentThread().threadId();

        long before = bean.getThreadAllocatedBytes(id);
        for (int i = 0; i < 10_000; i++) {
            keySet.find("unknown");
        }
        long unknown = bean.getThreadAllocatedBytes(id) - before;
        before = bean.getThreadAllocatedBytes(id);
        for (int i = 0; i < 10_000; i++) {
            keySet.find("k1");
        }
        long known = bean.getThreadAllocatedBytes(id) - before;

        assertThat(unknown).isLessThan(1024);
        assertThat(known).isLessThanOrEqualTo(16L * 10_000);
    }

    @Test
    @DisplayName("fromSource requires maximum staleness greater than refresh interval")
    void fromSourceValidatesMaxStaleness() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                JwksKeySet.fromSource(() -> "{}", 300 * SECOND, 30 * SECOND, 300 * SECOND, () -> 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximum staleness must be > the refresh interval");

        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                JwksKeySet.fromSource(() -> "{}", 300 * SECOND, 30 * SECOND, 200 * SECOND, () -> 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("maximum staleness must be > the refresh interval");
    }
}
