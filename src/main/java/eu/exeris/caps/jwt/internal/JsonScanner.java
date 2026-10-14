package eu.exeris.caps.jwt.internal;

import java.nio.charset.StandardCharsets;
import java.util.Collection;

/**
 * Strict, single-pass scanner over the members of one UTF-8 JSON object (RFC 8259), for the per-request
 * path. It builds no tree: a {@link MemberHandler} is called for each top-level member and takes only the
 * values it needs.
 *
 * <p>The whole document is validated even where the handler skips a value: syntax, string escapes and
 * control characters, number grammar, nesting depth, and nothing after the closing brace. Nesting depth is
 * bounded, so a hostile document cannot exhaust the stack. A handler must consume exactly one value per
 * member, and rejects a repeated member it cares about with {@link #duplicate()}, because a signer and
 * this verifier could otherwise read two {@code exp} or {@code alg} members differently.
 *
 * <p>Instances are not thread-safe and are used for one document. Malformed input throws
 * {@link IllegalArgumentException}.
 *
 * @since 0.1.0
 */
final class JsonScanner {

    /** Deepest nesting accepted; the top-level object is depth 0. */
    static final int MAX_DEPTH = 32;

    /** Called once per top-level member, positioned at the start of its value. */
    interface MemberHandler {
        void member(JsonScanner scanner);
    }

    private final byte[] bytes;
    private int pos;
    private int valueStart;
    private int nameStart;
    private int nameEnd;
    private boolean nameEscaped;
    private boolean integral;
    private long integer;

    JsonScanner(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Scans a document whose top-level value is an object.
     *
     * @param handler receives each top-level member
     * @throws IllegalArgumentException if the bytes are not exactly one well-formed JSON object
     */
    void scanObject(MemberHandler handler) {
        skipWhitespace();
        expect('{');
        skipWhitespace();
        if (peek() == '}') {
            pos++;
        } else {
            while (true) {
                skipWhitespace();
                readName();
                skipWhitespace();
                expect(':');
                skipWhitespace();
                int before = pos;
                valueStart = pos;
                handler.member(this);
                if (pos == before) {
                    throw new IllegalStateException("Handler left a member value unread");
                }
                skipWhitespace();
                byte c = next();
                if (c == '}') {
                    break;
                }
                if (c != ',') {
                    throw malformed("Expected ',' or '}'");
                }
            }
        }
        skipWhitespace();
        if (pos != bytes.length) {
            throw malformed("Trailing characters after JSON object");
        }
    }

    /** True if the current member's name is {@code expected}, comparing the name as JSON decodes it. */
    boolean nameIs(String expected) {
        if (nameEscaped) {
            return unescape(new String(bytes, nameStart, nameEnd - nameStart, StandardCharsets.UTF_8)).equals(expected);
        }
        int length = nameEnd - nameStart;
        if (length != expected.length()) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            if (bytes[nameStart + i] != (byte) expected.charAt(i) || expected.charAt(i) > 0x7f) {
                return false;
            }
        }
        return true;
    }

    /** The JSON kind of the next value: {@code '"'}, {@code '{'}, {@code '['}, {@code 'n'}, {@code 't'}, {@code 'f'} or {@code '0'} for a number. */
    char valueKind() {
        byte c = peek();
        return (c == '-' || (c >= '0' && c <= '9')) ? '0' : (char) c;
    }

    /** Reads a string value. */
    String readString() {
        expect('"');
        int start = pos;
        boolean escaped = false;
        while (true) {
            byte c = next();
            if (c == '"') {
                break;
            }
            if ((c & 0xff) < 0x20) {
                throw malformed("Unescaped control character in string");
            }
            if (c == '\\') {
                escaped = true;
                next();
            }
        }
        String raw = new String(bytes, start, pos - 1 - start, StandardCharsets.UTF_8);
        return escaped ? unescape(raw) : raw;
    }

    /**
     * Reads a number. Afterwards {@link #isInteger()} says whether it was an integer that fits a
     * {@code long}, and {@link #integer()} holds it; any other number is valid JSON but not an integer.
     */
    void readNumber() {
        boolean negative = false;
        if (peek() == '-') {
            negative = true;
            pos++;
        }
        long accumulated = 0;
        boolean fits = true;
        if (peek() == '0') {
            pos++;
        } else {
            int digitsStart = pos;
            while (pos < bytes.length && bytes[pos] >= '0' && bytes[pos] <= '9') {
                int digit = bytes[pos] - '0';
                if (accumulated < (Long.MIN_VALUE + digit) / 10) {
                    fits = false;
                } else {
                    accumulated = accumulated * 10 - digit;
                }
                pos++;
            }
            if (pos == digitsStart) {
                throw malformed("Expected digit");
            }
        }
        boolean fractionOrExponent = false;
        if (pos < bytes.length && bytes[pos] == '.') {
            fractionOrExponent = true;
            pos++;
            requireDigits();
        }
        if (pos < bytes.length && (bytes[pos] == 'e' || bytes[pos] == 'E')) {
            fractionOrExponent = true;
            pos++;
            if (pos < bytes.length && (bytes[pos] == '+' || bytes[pos] == '-')) {
                pos++;
            }
            requireDigits();
        }
        if (!negative && accumulated == Long.MIN_VALUE) {
            fits = false;
        }
        integral = !fractionOrExponent && fits;
        integer = integral ? (negative ? accumulated : -accumulated) : 0L;
    }

    /** Whether the number last read was an integer that fits a {@code long}. */
    boolean isInteger() {
        return integral;
    }

    /** The integer last read; meaningful only when {@link #isInteger()}. */
    long integer() {
        return integer;
    }

    /** Consumes a {@code null} literal if one is next. */
    boolean readNull() {
        if (peek() != 'n') {
            return false;
        }
        readLiteral("null");
        return true;
    }

    /**
     * Reads an array into {@code out}, which receives its string elements.
     *
     * @return true if every element was a string
     */
    boolean readStringArray(Collection<String> out) {
        expect('[');
        boolean allStrings = true;
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return true;
        }
        while (true) {
            skipWhitespace();
            if (peek() == '"') {
                out.add(readString());
            } else {
                allStrings = false;
                skipValue(2);
            }
            skipWhitespace();
            byte c = next();
            if (c == ']') {
                return allStrings;
            }
            if (c != ',') {
                throw malformed("Expected ',' or ']'");
            }
        }
    }

    /** Moves back to the start of the current member's value, so a second reader can take it. */
    void rewind() {
        pos = valueStart;
    }

    /**
     * Reads an array, validating all of it.
     *
     * @return true if one of its elements is a string equal to {@code wanted}
     */
    boolean readArrayContains(String wanted) {
        expect('[');
        boolean found = false;
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return false;
        }
        while (true) {
            skipWhitespace();
            if (peek() == '"') {
                found |= wanted.equals(readString());
            } else {
                skipValue(2);
            }
            skipWhitespace();
            byte c = next();
            if (c == ']') {
                return found;
            }
            if (c != ',') {
                throw malformed("Expected ',' or ']'");
            }
        }
    }

    /** Validates and discards the next value, a member value of the top-level object. */
    void skipValue() {
        skipValue(1);
    }

    /** Throws the error for a repeated member. */
    IllegalArgumentException duplicate() {
        return malformed("Duplicate JSON member name");
    }

    private void skipValue(int depth) {
        if (depth > MAX_DEPTH) {
            throw malformed("JSON nesting too deep");
        }
        skipWhitespace();
        switch (peek()) {
            case '{' -> skipObject(depth);
            case '[' -> skipArray(depth);
            case '"' -> readString();
            case 't' -> readLiteral("true");
            case 'f' -> readLiteral("false");
            case 'n' -> readLiteral("null");
            default -> {
                byte c = peek();
                if (c != '-' && (c < '0' || c > '9')) {
                    throw malformed("Unexpected character");
                }
                readNumber();
            }
        }
    }

    private void skipObject(int depth) {
        expect('{');
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            return;
        }
        while (true) {
            skipWhitespace();
            readName();
            skipWhitespace();
            expect(':');
            skipValue(depth + 1);
            skipWhitespace();
            byte c = next();
            if (c == '}') {
                return;
            }
            if (c != ',') {
                throw malformed("Expected ',' or '}'");
            }
        }
    }

    private void skipArray(int depth) {
        expect('[');
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return;
        }
        while (true) {
            skipValue(depth + 1);
            skipWhitespace();
            byte c = next();
            if (c == ']') {
                return;
            }
            if (c != ',') {
                throw malformed("Expected ',' or ']'");
            }
        }
    }

    private void readName() {
        if (peek() != '"') {
            throw malformed("Expected member name");
        }
        pos++;
        nameStart = pos;
        nameEscaped = false;
        while (true) {
            byte c = next();
            if (c == '"') {
                break;
            }
            if ((c & 0xff) < 0x20) {
                throw malformed("Unescaped control character in string");
            }
            if (c == '\\') {
                nameEscaped = true;
                next();
            }
        }
        nameEnd = pos - 1;
        if (nameEscaped) {
            unescape(new String(bytes, nameStart, nameEnd - nameStart, StandardCharsets.UTF_8));
        }
    }

    private static String unescape(String raw) {
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            if (++i >= raw.length()) {
                throw malformed("Truncated escape");
            }
            switch (raw.charAt(i)) {
                case '"' -> sb.append('"');
                case '\\' -> sb.append('\\');
                case '/' -> sb.append('/');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    if (i + 4 >= raw.length()) {
                        throw malformed("Truncated unicode escape");
                    }
                    int cp = 0;
                    for (int k = 1; k <= 4; k++) {
                        int d = Character.digit(raw.charAt(i + k), 16);
                        if (d < 0) {
                            throw malformed("Invalid unicode escape");
                        }
                        cp = (cp << 4) | d;
                    }
                    i += 4;
                    sb.append((char) cp);
                }
                default -> throw malformed("Invalid escape");
            }
        }
        return sb.toString();
    }

    private void readLiteral(String literal) {
        for (int i = 0; i < literal.length(); i++) {
            if (pos + i >= bytes.length || bytes[pos + i] != (byte) literal.charAt(i)) {
                throw malformed("Invalid literal");
            }
        }
        pos += literal.length();
    }

    private void requireDigits() {
        int start = pos;
        while (pos < bytes.length && bytes[pos] >= '0' && bytes[pos] <= '9') {
            pos++;
        }
        if (pos == start) {
            throw malformed("Expected digit");
        }
    }

    private void skipWhitespace() {
        while (pos < bytes.length) {
            byte c = bytes[pos];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            pos++;
        }
    }

    private byte peek() {
        if (pos >= bytes.length) {
            throw malformed("Unexpected end of JSON");
        }
        return bytes[pos];
    }

    private byte next() {
        byte c = peek();
        pos++;
        return c;
    }

    private void expect(char expected) {
        if (next() != expected) {
            throw malformed("Expected '" + expected + "'");
        }
    }

    private static IllegalArgumentException malformed(String message) {
        return new IllegalArgumentException(message);
    }
}
