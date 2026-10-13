package eu.exeris.caps.jwt.internal;

import java.nio.charset.StandardCharsets;

/**
 * Zero-allocation JSON scanner for standard JWT claims directly operating on UTF-8 bytes.
 *
 * <p>Extracts {@code exp}, {@code nbf}, {@code iat}, {@code sub}, {@code iss}, {@code tid} / {@code tenant_id},
 * and {@code aud} without Jackson, Gson, or AST allocations.
 *
 * @since 0.1.0
 */
public final class JsonClaimsScanner {

    public record ParsedClaims(
            String subject,
            String issuer,
            String tenantId,
            String audience,
            long expiresAt,
            long notBefore,
            long issuedAt
    ) {
    }

    private JsonClaimsScanner() {
    }

    /**
     * Scans UTF-8 JSON payload bytes and extracts standard JWT claims.
     *
     * @param bytes payload bytes; non-null
     * @return parsed claims or null if JSON is syntactically invalid
     */
    public static ParsedClaims scan(byte[] bytes) {
        if (bytes == null || bytes.length < 2) {
            return null;
        }

        int len = bytes.length;
        int i = 0;

        // Skip leading whitespace
        while (i < len && isWhitespace(bytes[i])) {
            i++;
        }
        if (i >= len || bytes[i] != '{') {
            return null;
        }
        i++;

        String sub = null;
        String iss = null;
        String tid = null;
        String aud = null;
        long exp = 0L;
        long nbf = 0L;
        long iat = 0L;

        while (i < len) {
            // Find key starting quote
            while (i < len && bytes[i] != '"' && bytes[i] != '}') {
                i++;
            }
            if (i >= len || bytes[i] == '}') {
                break;
            }
            i++; // skip opening quote

            int keyStart = i;
            while (i < len && bytes[i] != '"') {
                if (bytes[i] == '\\' && i + 1 < len) {
                    i++;
                }
                i++;
            }
            if (i >= len) {
                return null;
            }
            int keyEnd = i;
            i++; // skip closing quote

            // Find colon
            while (i < len && bytes[i] != ':') {
                if (bytes[i] == '}' || bytes[i] == '"') {
                    return null;
                }
                i++;
            }
            if (i >= len) {
                return null;
            }
            i++; // skip colon

            // Skip whitespace before value
            while (i < len && isWhitespace(bytes[i])) {
                i++;
            }
            if (i >= len) {
                return null;
            }

            int keyLen = keyEnd - keyStart;
            byte firstByte = bytes[i];

            if (firstByte == '"') {
                // String value
                i++; // skip opening quote
                int valStart = i;
                while (i < len && bytes[i] != '"') {
                    if (bytes[i] == '\\' && i + 1 < len) {
                        i++;
                    }
                    i++;
                }
                if (i >= len) {
                    return null;
                }
                int valEnd = i;
                i++; // skip closing quote

                if (matchesKey(bytes, keyStart, keyLen, "sub")) {
                    sub = new String(bytes, valStart, valEnd - valStart, StandardCharsets.UTF_8);
                } else if (matchesKey(bytes, keyStart, keyLen, "iss")) {
                    iss = new String(bytes, valStart, valEnd - valStart, StandardCharsets.UTF_8);
                } else if (matchesKey(bytes, keyStart, keyLen, "tid") || matchesKey(bytes, keyStart, keyLen, "tenant_id")) {
                    tid = new String(bytes, valStart, valEnd - valStart, StandardCharsets.UTF_8);
                } else if (matchesKey(bytes, keyStart, keyLen, "aud")) {
                    aud = new String(bytes, valStart, valEnd - valStart, StandardCharsets.UTF_8);
                }
            } else if (firstByte == '[') {
                // Array value (e.g. "aud": ["aud1", "aud2"])
                i++;
                int depth = 1;
                int arrStart = i;
                while (i < len && depth > 0) {
                    if (bytes[i] == '[') depth++;
                    else if (bytes[i] == ']') depth--;
                    else if (bytes[i] == '"') {
                        i++;
                        while (i < len && bytes[i] != '"') {
                            if (bytes[i] == '\\' && i + 1 < len) i++;
                            i++;
                        }
                    }
                    i++;
                }
                if (matchesKey(bytes, keyStart, keyLen, "aud")) {
                    // Extract first element or entire slice
                    aud = extractFirstArrayElement(bytes, arrStart, i - 1);
                }
            } else if ((firstByte >= '0' && firstByte <= '9') || firstByte == '-') {
                // Numeric value
                long val = 0;
                boolean neg = false;
                if (firstByte == '-') {
                    neg = true;
                    i++;
                }
                while (i < len && bytes[i] >= '0' && bytes[i] <= '9') {
                    val = val * 10 + (bytes[i] - '0');
                    i++;
                }
                if (neg) val = -val;

                if (matchesKey(bytes, keyStart, keyLen, "exp")) {
                    exp = val;
                } else if (matchesKey(bytes, keyStart, keyLen, "nbf")) {
                    nbf = val;
                } else if (matchesKey(bytes, keyStart, keyLen, "iat")) {
                    iat = val;
                }
            } else {
                // Skip other values (objects, booleans, null)
                while (i < len && bytes[i] != ',' && bytes[i] != '}') {
                    i++;
                }
            }

            // Skip until next comma or end of object
            while (i < len && bytes[i] != ',' && bytes[i] != '}') {
                i++;
            }
            if (i < len && bytes[i] == ',') {
                i++;
            }
        }

        return new ParsedClaims(sub, iss, tid, aud, exp, nbf, iat);
    }

    private static boolean matchesKey(byte[] bytes, int start, int len, String expected) {
        if (len != expected.length()) {
            return false;
        }
        for (int k = 0; k < len; k++) {
            if (bytes[start + k] != (byte) expected.charAt(k)) {
                return false;
            }
        }
        return true;
    }

    private static String extractFirstArrayElement(byte[] bytes, int start, int end) {
        int i = start;
        while (i < end && bytes[i] != '"') {
            i++;
        }
        if (i >= end) return null;
        i++; // skip opening quote
        int elemStart = i;
        while (i < end && bytes[i] != '"') {
            if (bytes[i] == '\\' && i + 1 < end) i++;
            i++;
        }
        if (i >= end) return null;
        return new String(bytes, elemStart, i - elemStart, StandardCharsets.UTF_8);
    }

    private static boolean isWhitespace(byte b) {
        return b == ' ' || b == '\t' || b == '\r' || b == '\n';
    }
}
