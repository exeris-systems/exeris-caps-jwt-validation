package eu.exeris.caps.jwt.internal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Strict JSON tree parser for the JWKS document (RFC 8259). The per-request path, the JOSE header and the
 * claim set of a token, never uses it: it is read by {@link JwsHeaderScanner} and {@link JwtClaimsScanner},
 * which build no tree.
 *
 * <p>Objects become {@link Map}, arrays {@link List}, strings {@link String}, integers {@link Long},
 * other numbers {@link Double}, and literals {@link Boolean} or {@code null}. A duplicate member name is
 * a parse error: two {@code exp} or {@code alg} members could otherwise be read differently by the
 * signer and by this verifier. Nesting depth is bounded, so a hostile document cannot exhaust the stack.
 *
 * @since 0.1.0
 */
public final class Json {

    private static final int MAX_DEPTH = 32;

    private final String text;
    private int pos;

    private Json(String text) {
        this.text = text;
    }

    /**
     * Parses a document whose top-level value is an object.
     *
     * @param text JSON text
     * @return the object's members in document order
     * @throws IllegalArgumentException if the text is not one well-formed JSON object
     */
    public static Map<String, Object> parseObject(String text) {
        Json parser = new Json(text);
        parser.skipWhitespace();
        if (parser.peek() != '{') {
            throw new IllegalArgumentException("JSON document is not an object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> value = (Map<String, Object>) parser.readValue(0);
        parser.skipWhitespace();
        if (parser.pos != text.length()) {
            throw new IllegalArgumentException("Trailing characters after JSON value");
        }
        return value;
    }

    private Object readValue(int depth) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON nesting too deep");
        }
        skipWhitespace();
        char c = peek();
        return switch (c) {
            case '{' -> readObject(depth);
            case '[' -> readArray(depth);
            case '"' -> readString();
            case 't' -> readLiteral("true", Boolean.TRUE);
            case 'f' -> readLiteral("false", Boolean.FALSE);
            case 'n' -> readLiteral("null", null);
            default -> {
                if (c == '-' || (c >= '0' && c <= '9')) {
                    yield readNumber();
                }
                throw new IllegalArgumentException("Unexpected character in JSON at " + pos);
            }
        };
    }

    private Map<String, Object> readObject(int depth) {
        expect('{');
        Map<String, Object> members = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            return Collections.unmodifiableMap(members);
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                throw new IllegalArgumentException("Expected member name at " + pos);
            }
            String name = readString();
            skipWhitespace();
            expect(':');
            Object value = readValue(depth + 1);
            if (members.containsKey(name)) {
                throw new IllegalArgumentException("Duplicate JSON member name");
            }
            members.put(name, value);
            skipWhitespace();
            char c = next();
            if (c == '}') {
                return Collections.unmodifiableMap(members);
            }
            if (c != ',') {
                throw new IllegalArgumentException("Expected ',' or '}' at " + (pos - 1));
            }
        }
    }

    private List<Object> readArray(int depth) {
        expect('[');
        List<Object> items = new ArrayList<>();
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return Collections.unmodifiableList(items);
        }
        while (true) {
            items.add(readValue(depth + 1));
            skipWhitespace();
            char c = next();
            if (c == ']') {
                return Collections.unmodifiableList(items);
            }
            if (c != ',') {
                throw new IllegalArgumentException("Expected ',' or ']' at " + (pos - 1));
            }
        }
    }

    private String readString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') {
                return sb.toString();
            }
            if (c < 0x20) {
                throw new IllegalArgumentException("Unescaped control character in JSON string");
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            char e = next();
            switch (e) {
                case '"' -> sb.append('"');
                case '\\' -> sb.append('\\');
                case '/' -> sb.append('/');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    if (pos + 4 > text.length()) {
                        throw new IllegalArgumentException("Truncated unicode escape");
                    }
                    int cp = 0;
                    for (int i = 0; i < 4; i++) {
                        int d = Character.digit(text.charAt(pos++), 16);
                        if (d < 0) {
                            throw new IllegalArgumentException("Invalid unicode escape");
                        }
                        cp = (cp << 4) | d;
                    }
                    sb.append((char) cp);
                }
                default -> throw new IllegalArgumentException("Invalid escape in JSON string");
            }
        }
    }

    private Object readNumber() {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        if (peek() == '0') {
            pos++;
        } else {
            requireDigits();
        }
        boolean integral = true;
        if (pos < text.length() && text.charAt(pos) == '.') {
            integral = false;
            pos++;
            requireDigits();
        }
        if (pos < text.length() && (text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
            integral = false;
            pos++;
            if (pos < text.length() && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) {
                pos++;
            }
            requireDigits();
        }
        String literal = text.substring(start, pos);
        if (integral) {
            try {
                return Long.parseLong(literal);
            } catch (NumberFormatException overflow) {
                return Double.parseDouble(literal);
            }
        }
        return Double.parseDouble(literal);
    }

    private void requireDigits() {
        int start = pos;
        while (pos < text.length() && text.charAt(pos) >= '0' && text.charAt(pos) <= '9') {
            pos++;
        }
        if (pos == start) {
            throw new IllegalArgumentException("Expected digit at " + pos);
        }
    }

    private Object readLiteral(String literal, Object value) {
        if (!text.startsWith(literal, pos)) {
            throw new IllegalArgumentException("Invalid JSON literal at " + pos);
        }
        pos += literal.length();
        return value;
    }

    private void skipWhitespace() {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            pos++;
        }
    }

    private char peek() {
        if (pos >= text.length()) {
            throw new IllegalArgumentException("Unexpected end of JSON");
        }
        return text.charAt(pos);
    }

    private char next() {
        char c = peek();
        pos++;
        return c;
    }

    private void expect(char expected) {
        if (next() != expected) {
            throw new IllegalArgumentException("Expected '" + expected + "' at " + (pos - 1));
        }
    }
}
