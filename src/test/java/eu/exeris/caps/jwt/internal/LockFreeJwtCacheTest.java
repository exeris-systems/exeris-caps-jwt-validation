package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtValidationResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LockFreeJwtCache Unit Tests")
class LockFreeJwtCacheTest {

    @Test
    @DisplayName("Caches and retrieves valid JWT result")
    void testCacheHit() {
        LockFreeJwtCache cache = new LockFreeJwtCache(64);
        long hash = 0x123456789abcdef0L;
        JwtValidationResult result = JwtValidationResult.valid("user-1", "issuer-1", "tenant-1", 2000000000L, 1000000000L);

        cache.put(hash, result);

        JwtValidationResult hit = cache.get(hash, 1500000000L);
        assertThat(hit).isNotNull();
        assertThat(hit.subject()).isEqualTo("user-1");
    }

    @Test
    @DisplayName("Returns null for expired cached entry")
    void testExpiredCacheEntry() {
        LockFreeJwtCache cache = new LockFreeJwtCache(64);
        long hash = 0xdeadbeefL;
        JwtValidationResult result = JwtValidationResult.valid("user-old", "iss", "tid", 1000L, 500L);

        cache.put(hash, result);

        // Lookup at time 2000L (after exp 1000L)
        JwtValidationResult hit = cache.get(hash, 2000L);
        assertThat(hit).isNull();
    }
}
