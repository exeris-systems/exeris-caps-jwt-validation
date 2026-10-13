package eu.exeris.caps.jwt.internal;

import eu.exeris.caps.jwt.api.JwtValidationResult;

/**
 * High-speed, bounded lock-free cache for verified JWT tokens.
 *
 * <p>Keyed by 64-bit hash of token signature with open addressing and bounded probing.
 * Allows repeated requests carrying the same valid JWT token to skip cryptographic
 * signature verification and JSON claims parsing entirely in sub-100ns.
 *
 * @since 0.1.0
 */
public final class LockFreeJwtCache {

    private static final int DEFAULT_CAPACITY = 16384;
    private static final int MAX_PROBE = 8;

    private final int mask;
    private final long[] keys;
    private final long[] expiresAt;
    private final JwtValidationResult[] results;

    public LockFreeJwtCache() {
        this(DEFAULT_CAPACITY);
    }

    public LockFreeJwtCache(int capacity) {
        int cap = 1;
        while (cap < capacity) {
            cap <<= 1;
        }
        this.mask = cap - 1;
        this.keys = new long[cap];
        this.expiresAt = new long[cap];
        this.results = new JwtValidationResult[cap];
    }

    /**
     * Looks up a cached validation result by 64-bit token/signature hash.
     *
     * @param hash 64-bit hash of token signature
     * @param nowSeconds current epoch seconds
     * @return cached result if present and not expired, or null
     */
    public JwtValidationResult get(long hash, long nowSeconds) {
        if (hash == 0L) {
            return null;
        }

        int base = (int) (hash & mask);
        for (int i = 0; i < MAX_PROBE; i++) {
            int slot = (base + i) & mask;
            long k = keys[slot];
            if (k == hash) {
                long exp = expiresAt[slot];
                if (exp > nowSeconds) {
                    return results[slot];
                } else {
                    // Expired entry
                    return null;
                }
            } else if (k == 0L) {
                return null;
            }
        }
        return null;
    }

    /**
     * Stores a verified validation result in the cache.
     *
     * @param hash 64-bit hash of token signature
     * @param result valid outcome
     */
    public void put(long hash, JwtValidationResult result) {
        if (hash == 0L || result == null || !result.isValid()) {
            return;
        }

        int base = (int) (hash & mask);
        int targetSlot = -1;

        for (int i = 0; i < MAX_PROBE; i++) {
            int slot = (base + i) & mask;
            long k = keys[slot];
            if (k == hash || k == 0L) {
                targetSlot = slot;
                break;
            }
        }

        if (targetSlot == -1) {
            // Evict at base slot (bounded LRU-approximation)
            targetSlot = base;
        }

        results[targetSlot] = result;
        expiresAt[targetSlot] = result.expiresAtSeconds();
        keys[targetSlot] = hash;
    }

    /**
     * Clears all cached entries.
     */
    public void clear() {
        java.util.Arrays.fill(keys, 0L);
        java.util.Arrays.fill(expiresAt, 0L);
        java.util.Arrays.fill(results, null);
    }
}
