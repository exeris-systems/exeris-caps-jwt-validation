package eu.exeris.caps.jwt.internal;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Reads the registered and configured claims the verifier decides on in one pass over the decoded claim
 * set, without building a tree. Members it does not read are validated and skipped.
 *
 * <p>A repeated member among the ones read is refused. A claim whose JSON value is {@code null} is the
 * same as an absent one. A claim of an unexpected type is recorded as such, so the caller can tell a wrong
 * type from an absence.
 *
 * @since 0.1.0
 */
final class JwtClaimsScanner implements JsonScanner.MemberHandler {

    private static final String[] FIXED = {"iss", "aud", "exp", "nbf", "iat", "sub", "sid", "roles", "scope", "scp"};
    private static final int ISS = 0;
    private static final int AUD = 1;
    private static final int EXP = 2;
    private static final int NBF = 3;
    private static final int IAT = 4;
    private static final int SUB = 5;
    private static final int SID = 6;
    private static final int ROLES = 7;
    private static final int SCOPE = 8;
    private static final int SCP = 9;
    private static final int TENANT = 10;

    /**
     * The claims of one token. A string claim is null when absent or not a string; {@code *Wrong} flags
     * say a value was present with the wrong type.
     */
    static final class Claims {
        String issuer;
        boolean audienceMatches;
        boolean hasExp;
        long exp;
        boolean hasNbf;
        long nbf;
        boolean hasIat;
        long iat;
        boolean iatWrong;
        String subject;
        String tenant;
        boolean tenantWrong;
        String sessionId;
        boolean sessionIdWrong;
        Set<String> roles = Set.of();
        boolean rolesWrong;
        String scopeString;
        boolean scopeWrong;
        Set<String> scp = Set.of();
        boolean scpWrong;
    }

    private final String audience;
    private final String tenantClaim;
    private final boolean[] seen = new boolean[TENANT + 1];
    private final Claims claims = new Claims();

    private JwtClaimsScanner(String audience, String tenantClaim) {
        this.audience = audience;
        this.tenantClaim = tenantClaim;
    }

    /**
     * Scans a decoded claim set.
     *
     * @param json UTF-8 claim set bytes
     * @param expectedAudience the audience {@code aud} must contain
     * @param tenantClaim the name of the tenant claim
     * @return the claims
     * @throws IllegalArgumentException if the bytes are not one well-formed JSON object, or repeat a claim
     *         this method reads
     */
    static Claims scan(byte[] json, String expectedAudience, String tenantClaim) {
        JwtClaimsScanner handler = new JwtClaimsScanner(expectedAudience, tenantClaim);
        new JsonScanner(json).scanObject(handler);
        return handler.claims;
    }

    @Override
    public void member(JsonScanner s) {
        boolean consumed = false;
        for (int slot = 0; slot <= TENANT; slot++) {
            String name = slot == TENANT ? tenantClaim : FIXED[slot];
            if (!s.nameIs(name)) {
                continue;
            }
            if (seen[slot]) {
                throw s.duplicate();
            }
            seen[slot] = true;
            if (consumed) {
                // A configured tenant claim named like a fixed one reads the same member again.
                s.rewind();
            }
            read(slot, s);
            consumed = true;
        }
        if (!consumed) {
            s.skipValue();
        }
    }

    private void read(int slot, JsonScanner s) {
        if (s.valueKind() == 'n') {
            s.readNull();
            return;
        }
        switch (slot) {
            case ISS -> claims.issuer = stringOrNull(s);
            case AUD -> readAudience(s);
            case EXP -> {
                if (readInteger(s)) {
                    claims.hasExp = true;
                    claims.exp = s.integer();
                }
            }
            case NBF -> {
                if (readInteger(s)) {
                    claims.hasNbf = true;
                    claims.nbf = s.integer();
                }
            }
            case IAT -> {
                if (readInteger(s)) {
                    claims.hasIat = true;
                    claims.iat = s.integer();
                } else {
                    claims.iatWrong = true;
                }
            }
            case SUB -> claims.subject = stringOrNull(s);
            case SID -> {
                claims.sessionId = stringOrNull(s);
                claims.sessionIdWrong = claims.sessionId == null;
            }
            case ROLES -> {
                Set<String> out = new LinkedHashSet<>();
                if (readStrings(s, out)) {
                    claims.roles = out;
                } else {
                    claims.rolesWrong = true;
                }
            }
            case SCOPE -> {
                claims.scopeString = stringOrNull(s);
                claims.scopeWrong = claims.scopeString == null;
            }
            case SCP -> {
                Set<String> out = new LinkedHashSet<>();
                if (readStrings(s, out)) {
                    claims.scp = out;
                } else {
                    claims.scpWrong = true;
                }
            }
            case TENANT -> {
                claims.tenant = stringOrNull(s);
                claims.tenantWrong = claims.tenant == null;
            }
            default -> throw new IllegalStateException("Unknown claim slot " + slot);
        }
    }

    private void readAudience(JsonScanner s) {
        char kind = s.valueKind();
        if (kind == '"') {
            claims.audienceMatches = audience.equals(s.readString());
        } else if (kind == '[') {
            claims.audienceMatches = s.readArrayContains(audience);
        } else {
            s.skipValue();
        }
    }

    private static boolean readInteger(JsonScanner s) {
        if (s.valueKind() != '0') {
            s.skipValue();
            return false;
        }
        s.readNumber();
        return s.isInteger();
    }

    private static boolean readStrings(JsonScanner s, Set<String> out) {
        if (s.valueKind() != '[') {
            s.skipValue();
            return false;
        }
        return s.readStringArray(out);
    }

    private static String stringOrNull(JsonScanner s) {
        if (s.valueKind() == '"') {
            return s.readString();
        }
        s.skipValue();
        return null;
    }
}
