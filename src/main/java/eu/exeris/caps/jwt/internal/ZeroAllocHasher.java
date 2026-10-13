package eu.exeris.caps.jwt.internal;

/**
 * Zero-allocation 64-bit hasher for CharSequence and primitive values.
 *
 * @since 0.1.0
 */
public final class ZeroAllocHasher {

    private static final long SEED = 0x9e3779b97f4a7c15L;
    private static final long M1 = 0xff51afd7ed558ccdL;
    private static final long M2 = 0xc4ceb9fe1a85ec53L;

    private ZeroAllocHasher() {
    }

    /**
     * Hashes a CharSequence without allocating String objects.
     */
    public static long hash(CharSequence cs) {
        if (cs == null || cs.isEmpty()) {
            return SEED;
        }

        long h = SEED ^ cs.length();
        int len = cs.length();
        for (int i = 0; i < len; i++) {
            h ^= cs.charAt(i);
            h *= M1;
            h = Long.rotateLeft(h, 31);
        }

        long result = fmix64(h);
        return result == 0L ? 1L : result;
    }

    /**
     * Hashes a sub-sequence without allocating String or SubSequence objects.
     */
    public static long hashSubSequence(CharSequence cs, int start, int end) {
        int len = end - start;
        if (len <= 0) {
            return SEED;
        }

        long h = SEED ^ len;
        for (int i = start; i < end; i++) {
            h ^= cs.charAt(i);
            h *= M1;
            h = Long.rotateLeft(h, 31);
        }

        long result = fmix64(h);
        return result == 0L ? 1L : result;
    }

    private static long fmix64(long k) {
        k ^= k >>> 33;
        k *= M1;
        k ^= k >>> 33;
        k *= M2;
        k ^= k >>> 33;
        return k;
    }
}
