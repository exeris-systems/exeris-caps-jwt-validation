package eu.exeris.caps.jwt.internal;

/**
 * Reads the JOSE header parameters the verifier decides on, {@code alg}, {@code kid} and {@code crit},
 * in one pass over the decoded header bytes and without building a tree.
 *
 * <p>A repeated {@code alg}, {@code kid} or {@code crit} member is refused. A parameter that is absent,
 * {@code null} or not a string is reported as {@code null}.
 *
 * @since 0.1.0
 */
final class JwsHeaderScanner implements JsonScanner.MemberHandler {

    /**
     * The header parameters of one token.
     *
     * @param alg the {@code alg} string, or null if absent or not a string
     * @param kid the {@code kid} string, or null if absent or not a string
     * @param critical whether a {@code crit} member is present
     */
    record Header(String alg, String kid, boolean critical) {
    }

    private String alg;
    private String kid;
    private boolean critical;
    private boolean seenAlg;
    private boolean seenKid;
    private boolean seenCrit;

    private JwsHeaderScanner() {
    }

    /**
     * Scans a decoded JOSE header.
     *
     * @param json UTF-8 header bytes
     * @return the header parameters
     * @throws IllegalArgumentException if the bytes are not one well-formed JSON object, or repeat a
     *         parameter this method reads
     */
    static Header scan(byte[] json) {
        JwsHeaderScanner handler = new JwsHeaderScanner();
        new JsonScanner(json).scanObject(handler);
        return new Header(handler.alg, handler.kid, handler.critical);
    }

    @Override
    public void member(JsonScanner s) {
        if (s.nameIs("alg")) {
            if (seenAlg) {
                throw s.duplicate();
            }
            seenAlg = true;
            alg = stringOrNull(s);
        } else if (s.nameIs("kid")) {
            if (seenKid) {
                throw s.duplicate();
            }
            seenKid = true;
            kid = stringOrNull(s);
        } else if (s.nameIs("crit")) {
            if (seenCrit) {
                throw s.duplicate();
            }
            seenCrit = true;
            critical = true;
            s.skipValue();
        } else {
            s.skipValue();
        }
    }

    private static String stringOrNull(JsonScanner s) {
        if (s.valueKind() == '"') {
            return s.readString();
        }
        s.skipValue();
        return null;
    }
}
