package eu.exeris.caps.jwt.internal;

import java.util.Arrays;

/**
 * Fast, allocation-free Base64URL decoder for {@link CharSequence} slices.
 *
 * <p>Supports RFC 4648 URL-safe alphabet ({@code '-'} and {@code '_'}) with or without padding.
 *
 * @since 0.1.0
 */
public final class Base64UrlDecoder {

    private static final byte[] DECODE_TABLE = new byte[128];

    static {
        Arrays.fill(DECODE_TABLE, (byte) -1);
        for (char c = 'A'; c <= 'Z'; c++) {
            DECODE_TABLE[c] = (byte) (c - 'A');
        }
        for (char c = 'a'; c <= 'z'; c++) {
            DECODE_TABLE[c] = (byte) (c - 'a' + 26);
        }
        for (char c = '0'; c <= '9'; c++) {
            DECODE_TABLE[c] = (byte) (c - '0' + 52);
        }
        DECODE_TABLE['-'] = 62;
        DECODE_TABLE['_'] = 63;
    }

    private Base64UrlDecoder() {
    }

    /**
     * Calculates the exact decoded byte count for a given Base64URL slice.
     *
     * @return number of bytes, or -1 if the length is syntactically invalid
     */
    public static int decodedLength(CharSequence s, int start, int end) {
        int len = end - start;
        if (len <= 0) {
            return 0;
        }
        while (len > 0 && s.charAt(start + len - 1) == '=') {
            len--;
        }
        int rem = len % 4;
        if (rem == 1) {
            return -1; // Single dangling character is illegal Base64
        }
        int fullBlocks = len / 4;
        int bytes = fullBlocks * 3;
        if (rem == 2) {
            bytes += 1;
        } else if (rem == 3) {
            bytes += 2;
        }
        return bytes;
    }

    /**
     * Decodes a Base64URL slice into the provided destination byte array.
     *
     * @param s source sequence
     * @param start start index (inclusive)
     * @param end end index (exclusive)
     * @param out target byte array
     * @param outOffset starting index in target byte array
     * @return true if decoding succeeded, false if invalid characters or length were encountered
     */
    public static boolean decode(CharSequence s, int start, int end, byte[] out, int outOffset) {
        int len = end - start;
        while (len > 0 && s.charAt(start + len - 1) == '=') {
            len--;
        }
        if (len == 0) {
            return true;
        }
        int rem = len % 4;
        if (rem == 1) {
            return false;
        }

        int fullBlocks = len / 4;
        int srcIdx = start;
        int dstIdx = outOffset;

        for (int i = 0; i < fullBlocks; i++) {
            int b0 = decodeChar(s.charAt(srcIdx++));
            int b1 = decodeChar(s.charAt(srcIdx++));
            int b2 = decodeChar(s.charAt(srcIdx++));
            int b3 = decodeChar(s.charAt(srcIdx++));
            if ((b0 | b1 | b2 | b3) < 0) {
                return false;
            }
            int bits = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;
            out[dstIdx++] = (byte) (bits >> 16);
            out[dstIdx++] = (byte) (bits >> 8);
            out[dstIdx++] = (byte) bits;
        }

        if (rem == 2) {
            int b0 = decodeChar(s.charAt(srcIdx++));
            int b1 = decodeChar(s.charAt(srcIdx++));
            if ((b0 | b1) < 0) {
                return false;
            }
            int bits = (b0 << 6) | b1;
            out[dstIdx] = (byte) (bits >> 4);
        } else if (rem == 3) {
            int b0 = decodeChar(s.charAt(srcIdx++));
            int b1 = decodeChar(s.charAt(srcIdx++));
            int b2 = decodeChar(s.charAt(srcIdx++));
            if ((b0 | b1 | b2) < 0) {
                return false;
            }
            int bits = (b0 << 12) | (b1 << 6) | b2;
            out[dstIdx++] = (byte) (bits >> 10);
            out[dstIdx] = (byte) (bits >> 2);
        }

        return true;
    }

    /**
     * Helper to decode into a freshly allocated byte array.
     */
    public static byte[] decodeToBytes(CharSequence s, int start, int end) {
        int len = decodedLength(s, start, end);
        if (len < 0) {
            return null;
        }
        byte[] out = new byte[len];
        if (!decode(s, start, end, out, 0)) {
            return null;
        }
        return out;
    }

    private static int decodeChar(char c) {
        if (c >= 128) {
            return -1;
        }
        return DECODE_TABLE[c];
    }
}
