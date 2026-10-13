package eu.exeris.caps.jwt.internal;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

/**
 * High-performance, constant-time HMAC-SHA256 signature validator.
 *
 * <p>Virtual Thread-safe and stateless per ADR-007 (ThreadLocal is strictly BANNED).
 * Uses cloned or instantiated {@link Mac} instances and feeds {@link CharSequence} slices
 * directly into the digest via ephemeral chunk buffers.
 *
 * @since 0.1.0
 */
public final class HmacSha256Validator {

    private static final String ALGORITHM = "HmacSHA256";
    private static final int CHUNK_SIZE = 512;

    private final byte[] secretKeyBytes;
    private final SecretKeySpec keySpec;
    private final Mac prototypeMac;

    public HmacSha256Validator(byte[] secretKeyBytes) {
        if (secretKeyBytes == null || secretKeyBytes.length == 0) {
            throw new IllegalArgumentException("Secret key must not be null or empty");
        }
        this.secretKeyBytes = secretKeyBytes.clone();
        this.keySpec = new SecretKeySpec(this.secretKeyBytes, ALGORITHM);
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(this.keySpec);
            this.prototypeMac = mac;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize Mac: " + ALGORITHM, e);
        }
    }

    private Mac createMac() {
        try {
            return (Mac) prototypeMac.clone();
        } catch (CloneNotSupportedException e) {
            try {
                Mac mac = Mac.getInstance(ALGORITHM);
                mac.init(keySpec);
                return mac;
            } catch (Exception ex) {
                throw new IllegalStateException("Failed to initialize Mac: " + ALGORITHM, ex);
            }
        }
    }

    /**
     * Verifies that the HMAC-SHA256 of {@code input[start..end]} matches {@code expectedSignature}.
     *
     * @param input character sequence containing signing input (header.payload)
     * @param start start index (inclusive)
     * @param end end index (exclusive)
     * @param expectedSignature raw decoded signature bytes (32 bytes for HS256)
     * @return true if valid, false if invalid or tampered
     */
    public boolean verify(CharSequence input, int start, int end, byte[] expectedSignature) {
        if (expectedSignature == null || expectedSignature.length != 32) {
            return false;
        }

        Mac mac = createMac();
        int len = end - start;
        byte[] buf = new byte[Math.min(len, CHUNK_SIZE)];

        int pos = 0;
        for (int i = 0; i < len; i++) {
            char c = input.charAt(start + i);
            buf[pos++] = (byte) (c <= 127 ? c : '?');
            if (pos == buf.length) {
                mac.update(buf, 0, pos);
                pos = 0;
            }
        }
        if (pos > 0) {
            mac.update(buf, 0, pos);
        }

        byte[] computed = mac.doFinal();
        return MessageDigest.isEqual(computed, expectedSignature);
    }

    /**
     * Signs the input slice and returns the raw 32-byte HMAC-SHA256 signature.
     */
    public byte[] sign(CharSequence input, int start, int end) {
        Mac mac = createMac();
        int len = end - start;
        byte[] buf = new byte[Math.min(len, CHUNK_SIZE)];

        int pos = 0;
        for (int i = 0; i < len; i++) {
            char c = input.charAt(start + i);
            buf[pos++] = (byte) (c <= 127 ? c : '?');
            if (pos == buf.length) {
                mac.update(buf, 0, pos);
                pos = 0;
            }
        }
        if (pos > 0) {
            mac.update(buf, 0, pos);
        }

        return mac.doFinal();
    }
}
