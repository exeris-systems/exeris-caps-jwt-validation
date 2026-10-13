package eu.exeris.caps.jwt.internal;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Resolves Ed25519 public keys from JWKS documents or key suppliers.
 *
 * @since 0.1.0
 */
public final class JwksKeyResolver implements Function<String, PublicKey> {

    private static final byte[] ED25519_X509_HEADER = new byte[]{
            0x30, 0x2a,
            0x30, 0x05,
            0x06, 0x03, (byte) 0x2b, 0x65, 0x70,
            0x03, 0x21,
            0x00
    };

    private final Supplier<String> jwksSupplier;
    private final Function<String, PublicKey> fallbackResolver;
    private volatile String cachedJwksJson;
    private volatile Map<String, PublicKey> cachedKeys = Map.of();
    private volatile PublicKey singleKey;

    public JwksKeyResolver(Supplier<String> jwksSupplier, Function<String, PublicKey> fallbackResolver) {
        this.jwksSupplier = jwksSupplier;
        this.fallbackResolver = fallbackResolver;
    }

    public static JwksKeyResolver fromStaticJwks(String jwksJson) {
        Objects.requireNonNull(jwksJson, "jwksJson");
        JwksKeyResolver resolver = new JwksKeyResolver(() -> jwksJson, null);
        resolver.refreshKeys(jwksJson);
        return resolver;
    }

    public static JwksKeyResolver fromSingleKey(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        JwksKeyResolver resolver = new JwksKeyResolver(null, kid -> publicKey);
        resolver.singleKey = publicKey;
        return resolver;
    }

    public static JwksKeyResolver fromSupplier(Supplier<String> supplier) {
        Objects.requireNonNull(supplier, "supplier");
        return new JwksKeyResolver(supplier, null);
    }

    @Override
    public PublicKey apply(String kid) {
        if (singleKey != null && (kid == null || kid.isBlank() || cachedKeys.isEmpty())) {
            return singleKey;
        }

        if (jwksSupplier != null) {
            String currentJwks = jwksSupplier.get();
            if (currentJwks != null && !currentJwks.equals(cachedJwksJson)) {
                refreshKeys(currentJwks);
            }
        }

        if (kid != null && !kid.isBlank()) {
            PublicKey pk = cachedKeys.get(kid);
            if (pk != null) {
                return pk;
            }
        }

        if (fallbackResolver != null) {
            return fallbackResolver.apply(kid);
        }
        return null;
    }

    private synchronized void refreshKeys(String jwksJson) {
        if (jwksJson == null || jwksJson.isBlank()) {
            return;
        }
        Map<String, PublicKey> parsed = parseJwks(jwksJson);
        this.cachedKeys = parsed;
        this.cachedJwksJson = jwksJson;
    }

    public static Map<String, PublicKey> parseJwks(String jwksJson) {
        Map<String, PublicKey> result = new HashMap<>();
        try {
            int idx = jwksJson.indexOf("\"keys\"");
            if (idx < 0) {
                return result;
            }
            int openBracket = jwksJson.indexOf('[', idx);
            int closeBracket = jwksJson.lastIndexOf(']');
            if (openBracket < 0 || closeBracket <= openBracket) {
                return result;
            }

            String arrayContent = jwksJson.substring(openBracket + 1, closeBracket);
            int pos = 0;
            while (pos < arrayContent.length()) {
                int objStart = arrayContent.indexOf('{', pos);
                if (objStart < 0) break;
                int objEnd = findMatchingBrace(arrayContent, objStart);
                if (objEnd < 0) break;

                String keyObj = arrayContent.substring(objStart, objEnd + 1);
                pos = objEnd + 1;

                String kid = extractStringField(keyObj, "kid");
                String kty = extractStringField(keyObj, "kty");
                String x = extractStringField(keyObj, "x");
                String crv = extractStringField(keyObj, "crv");

                PublicKey pk = null;
                if (("OKP".equalsIgnoreCase(kty) || kty == null) && x != null && (crv == null || "Ed25519".equalsIgnoreCase(crv))) {
                    pk = decodeEd25519PublicKey(x);
                } else if ("RSA".equalsIgnoreCase(kty)) {
                    String n = extractStringField(keyObj, "n");
                    String e = extractStringField(keyObj, "e");
                    if (n != null && e != null) {
                        pk = decodeRsaPublicKey(n, e);
                    }
                } else if ("EC".equalsIgnoreCase(kty)) {
                    String y = extractStringField(keyObj, "y");
                    if (x != null && y != null && (crv == null || "P-256".equalsIgnoreCase(crv) || "secp256r1".equalsIgnoreCase(crv))) {
                        pk = decodeEcP256PublicKey(x, y);
                    }
                }

                if (pk != null) {
                    if (kid != null) {
                        result.put(kid, pk);
                    } else {
                        result.put("default", pk);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return Map.copyOf(result);
    }

    private static int findMatchingBrace(String text, int start) {
        int depth = 0;
        boolean inQuotes = false;
        for (int i = start; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"' && (i == 0 || text.charAt(i - 1) != '\\')) {
                inQuotes = !inQuotes;
            } else if (!inQuotes) {
                if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) return i;
                }
            }
        }
        return -1;
    }

    private static String extractStringField(String json, String field) {
        String pattern = "\"" + field + "\"";
        int idx = json.indexOf(pattern);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + pattern.length());
        if (colon < 0) return null;
        int q1 = json.indexOf('"', colon);
        if (q1 < 0) return null;
        int q2 = json.indexOf('"', q1 + 1);
        while (q2 > 0 && json.charAt(q2 - 1) == '\\') {
            q2 = json.indexOf('"', q2 + 1);
        }
        if (q2 < 0) return null;
        return json.substring(q1 + 1, q2);
    }

    public static PublicKey decodeEd25519PublicKey(String base64UrlX) {
        try {
            byte[] raw32 = Base64UrlDecoder.decodeToBytes(base64UrlX, 0, base64UrlX.length());
            if (raw32 == null || raw32.length != 32) {
                return null;
            }
            byte[] x509 = new byte[ED25519_X509_HEADER.length + 32];
            System.arraycopy(ED25519_X509_HEADER, 0, x509, 0, ED25519_X509_HEADER.length);
            System.arraycopy(raw32, 0, x509, ED25519_X509_HEADER.length, 32);

            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return kf.generatePublic(new X509EncodedKeySpec(x509));
        } catch (Exception e) {
            return null;
        }
    }

    public static PublicKey decodeRsaPublicKey(String base64UrlN, String base64UrlE) {
        try {
            byte[] nBytes = Base64UrlDecoder.decodeToBytes(base64UrlN, 0, base64UrlN.length());
            byte[] eBytes = Base64UrlDecoder.decodeToBytes(base64UrlE, 0, base64UrlE.length());
            if (nBytes == null || eBytes == null) {
                return null;
            }
            java.math.BigInteger modulus = new java.math.BigInteger(1, nBytes);
            java.math.BigInteger exponent = new java.math.BigInteger(1, eBytes);
            java.security.spec.RSAPublicKeySpec spec = new java.security.spec.RSAPublicKeySpec(modulus, exponent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            return null;
        }
    }

    public static PublicKey decodeEcP256PublicKey(String base64UrlX, String base64UrlY) {
        try {
            byte[] xBytes = Base64UrlDecoder.decodeToBytes(base64UrlX, 0, base64UrlX.length());
            byte[] yBytes = Base64UrlDecoder.decodeToBytes(base64UrlY, 0, base64UrlY.length());
            if (xBytes == null || yBytes == null) {
                return null;
            }
            java.math.BigInteger xInt = new java.math.BigInteger(1, xBytes);
            java.math.BigInteger yInt = new java.math.BigInteger(1, yBytes);
            java.security.spec.ECPoint point = new java.security.spec.ECPoint(xInt, yInt);

            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
            params.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
            java.security.spec.ECParameterSpec ecParams = params.getParameterSpec(java.security.spec.ECParameterSpec.class);

            java.security.spec.ECPublicKeySpec spec = new java.security.spec.ECPublicKeySpec(point, ecParams);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            return null;
        }
    }
}
