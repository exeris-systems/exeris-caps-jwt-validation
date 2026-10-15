package eu.exeris.caps.jwt.internal;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

/** Key pairs, JWKS documents and signed tokens for tests. */
public final class TestTokens {

    public static final String ISSUER = "https://identity.example.test";
    public static final String AUDIENCE = "exeris-console";
    public static final String SUBJECT = "7d3c1f0e-2b4a-4c8e-9f10-1a2b3c4d5e6f";
    public static final String TENANT = "0b9e8d7c-6a5f-4e3d-8c2b-1a0f9e8d7c6b";
    public static final String SESSION = "5f4e3d2c-1b0a-4f9e-8d7c-6b5a4f3e2d1c";
    public static final long NOW = 1_800_000_000L;

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private TestTokens() {
    }

    public static KeyPair ed25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair rsa(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String okpJwk(String kid, KeyPair pair) {
        byte[] encoded = pair.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        return "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"sig\",\"alg\":\"EdDSA\",\"kid\":\"" + kid
                + "\",\"x\":\"" + B64.encodeToString(raw) + "\"}";
    }

    public static String rsaJwk(String kid, KeyPair pair) {
        RSAPublicKey key = (RSAPublicKey) pair.getPublic();
        return "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"" + kid + "\",\"n\":\"" + B64.encodeToString(unsigned(key.getModulus()))
                + "\",\"e\":\"" + B64.encodeToString(unsigned(key.getPublicExponent())) + "\"}";
    }

    public static String jwks(String... jwks) {
        return "{\"keys\":[" + String.join(",", jwks) + "]}";
    }

    /** Claims of a token that the default test policy accepts at {@link #NOW}. */
    public static String validClaims() {
        return "{\"iss\":\"" + ISSUER + "\",\"aud\":\"" + AUDIENCE + "\",\"sub\":\"" + SUBJECT
                + "\",\"tid\":\"" + TENANT + "\",\"sid\":\"" + SESSION
                + "\",\"roles\":[\"owner\",\"admin\"],\"scope\":\"tenants:read tenants:write\""
                + ",\"iat\":" + (NOW - 10) + ",\"nbf\":" + (NOW - 10) + ",\"exp\":" + (NOW + 300) + "}";
    }

    public static String eddsa(String kid, PrivateKey key, String claims) {
        return sign("{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}", claims, "Ed25519", key);
    }

    public static String rs256(String kid, PrivateKey key, String claims) {
        return sign("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}", claims, "SHA256withRSA", key);
    }

    /** Signs with {@code jcaAlgorithm} under an arbitrary header, so a test can lie about {@code alg}. */
    public static String sign(String headerJson, String claimsJson, String jcaAlgorithm, PrivateKey key) {
        String input = encode(headerJson) + "." + encode(claimsJson);
        try {
            Signature signer = Signature.getInstance(jcaAlgorithm);
            signer.initSign(key);
            signer.update(input.getBytes(StandardCharsets.US_ASCII));
            return input + "." + B64.encodeToString(signer.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A token whose signature segment is arbitrary bytes. */
    public static String unsigned(String headerJson, String claimsJson, byte[] signature) {
        return encode(headerJson) + "." + encode(claimsJson) + "." + B64.encodeToString(signature);
    }

    public static String encode(String json) {
        return B64.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }
}
