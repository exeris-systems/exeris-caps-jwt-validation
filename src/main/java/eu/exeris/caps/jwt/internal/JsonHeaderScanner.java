package eu.exeris.caps.jwt.internal;

import java.nio.charset.StandardCharsets;

/**
 * Fast, allocation-conscious scanner for JWT header parameters (alg, kid, typ).
 *
 * @since 0.1.0
 */
public final class JsonHeaderScanner {

    public record ParsedHeader(
            String alg,
            String kid,
            String typ
    ) {}

    private JsonHeaderScanner() {}

    public static ParsedHeader scan(byte[] bytes) {
        if (bytes == null || bytes.length < 2) {
            return null;
        }

        int len = bytes.length;
        int i = 0;

        while (i < len && isWhitespace(bytes[i])) {
            i++;
        }
        if (i >= len || bytes[i] != '{') {
            return null;
        }
        i++;

        String alg = null;
        String kid = null;
        String typ = null;

        while (i < len) {
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

            while (i < len && isWhitespace(bytes[i])) {
                i++;
            }
            if (i >= len) {
                return null;
            }

            int keyLen = keyEnd - keyStart;
            boolean isAlg = keyLen == 3 && bytes[keyStart] == 'a' && bytes[keyStart + 1] == 'l' && bytes[keyStart + 2] == 'g';
            boolean isKid = keyLen == 3 && bytes[keyStart] == 'k' && bytes[keyStart + 1] == 'i' && bytes[keyStart + 2] == 'd';
            boolean isTyp = keyLen == 3 && bytes[keyStart] == 't' && bytes[keyStart + 1] == 'y' && bytes[keyStart + 2] == 'p';

            if (bytes[i] == '"') {
                i++;
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

                String val = new String(bytes, valStart, valEnd - valStart, StandardCharsets.UTF_8);
                if (isAlg) alg = val;
                else if (isKid) kid = val;
                else if (isTyp) typ = val;
            } else {
                // skip non-string value
                while (i < len && bytes[i] != ',' && bytes[i] != '}') {
                    i++;
                }
            }

            while (i < len && isWhitespace(bytes[i])) {
                i++;
            }
            if (i < len && bytes[i] == ',') {
                i++;
            }
        }

        return new ParsedHeader(alg, kid, typ);
    }

    private static boolean isWhitespace(byte b) {
        return b == ' ' || b == '\t' || b == '\n' || b == '\r';
    }
}
