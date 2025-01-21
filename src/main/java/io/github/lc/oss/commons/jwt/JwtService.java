package io.github.lc.oss.commons.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;

import io.github.lc.oss.commons.signing.Algorithm;
import io.github.lc.oss.commons.signing.Algorithms;

public abstract class JwtService {
    private final JwtRevocationList revocationList = new JwtRevocationList();

    public JwtService() {
        this.assertNotMixedAlgorithms();
    }

    /**
     * Contract: If the <code>alg</code> argument is null then this method must
     * return <code>false</code>. This method may return <code>true</code> if and
     * only if the provided algorithm is acceptable to the implementer.<br />
     * <br />
     * DANGER: Never return true for both an HMAC algorithm and a key based
     * algorithm! This would allow an attacker to use the public key as the shared
     * HMAC secret thus enabling falsified tokens!
     */
    public abstract boolean isAlgorithmAllowed(Algorithm alg);

    public abstract Set<String> getIssuers();

    public abstract String getAudience();

    protected abstract long now();

    /**
     * Default implementation does not log anything. To log a message override the
     * {@linkplain #log(String, Throwable)} method.
     */
    protected void log(String message) {
        this.log(message, null);
    }

    /**
     * Default implementation does not log anything. To log a message override this
     * method.
     */
    protected void log(String message, Throwable ex) {
    }

    protected JwtRevocationList getRevocationList() {
        return this.revocationList;
    }

    public void invalidate(Jwt token) {
        if (token == null) {
            return;
        }

        this.getRevocationList().revoke(token);
    }

    public void invalidate(String signature, long expiration) {
        if (signature == null) {
            return;
        }

        if (expiration < 0) {
            throw new IllegalArgumentException(
                    "Expiration must be positive number but was " + Long.toString(expiration));
        }

        this.getRevocationList().revoke(signature, expiration + 10000);
    }

    public boolean isRevoked(Jwt token) {
        return this.isRevoked(token.getSignature());
    }

    public boolean isRevoked(String signature) {
        return this.getRevocationList().isRevoked(signature);
    }

    public Jwt issue(Algorithm alg, long expirationMillis, String subject, String issuer, String audience) {
        return this.issue(alg, expirationMillis, null, subject, issuer, audience);
    }

    public Jwt issue(Algorithm alg, Long expirationMillis, Long notBeforeMillis, String subject, String issuer,
            String... audience) {
        if (Util.isBlank(alg) || //
                Util.isBlank(expirationMillis) || //
                Util.isBlank(subject) || //
                Util.isBlank(issuer) || //
                Util.isBlank(audience)) {
            throw new IllegalArgumentException("All parameters are required");
        }
        Long now = System.currentTimeMillis() / 1000l;
        Long expires = expirationMillis / 1000l;
        Long notBefore = notBeforeMillis == null ? now : notBeforeMillis / 1000l;

        if (expires <= now) {
            throw new IllegalArgumentException("Expiration must be in the future");
        }

        if (expires < notBefore) {
            throw new IllegalArgumentException("'Not Before' cannot come after 'expires'");
        }

        Jwt t = new Jwt();
        t.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        t.getHeader().setAlgorithm(alg);
        t.getPayload().setSubject(subject);
        t.getPayload().setIssuedAt(now);
        t.getPayload().setNotBefore(notBefore);
        t.getPayload().setExpiration(expires);
        t.getPayload().setTokenId(UUID.randomUUID().toString());
        t.getPayload().setIssuer(issuer);
        t.getPayload().setAudience(audience);
        return t;
    }

    public Jwt refresh(Jwt token, long maxAge, long timeout) {
        /* Revoke old token, we will be issuing a new one */
        this.invalidate(token);

        Long issuedAt = token.getIssuedAt() * 1000;
        long max = issuedAt + maxAge;
        long expires = this.now() + timeout;
        if (expires > max) {
            expires = max;
        }
        token.setExpirationMillis(expires);
        token.getPayload().setTokenId(UUID.randomUUID().toString());

        return token;
    }

    public String signAndEncode(Jwt token) {
        return this.signAndEncode((byte[]) null, token);
    }

    public String signAndEncode(byte[] secret, Jwt token) {
        byte[] s = this.getSignSecret(token.getHeader(), secret);
        if (s == null) {
            throw new RuntimeException("Secret cannot be null");
        }
        token.setSignature(
                token.getAlgorithm().getSignature(s, Util.toJsonNoSignature(token).getBytes(StandardCharsets.UTF_8)));
        return Util.toJson(token);
    }

    public Jwt validate(String encoded) {
        return this.validate(encoded, null);
    }

    public Jwt validate(String encoded, String audience) {
        return this.validate(null, encoded, audience);
    }

    public Jwt validate(byte[] secret, String encoded, String audience) {
        String[] parts = this.parseToken(encoded);
        if (parts == null) {
            this.log("Token parsed to null");
            return null;
        }

        if (this.getRevocationList().isRevoked(parts[2])) {
            this.log("Token is revoked by signature");
            return null;
        }

        try {
            JwtHeader header = this.fromBase64Json(parts[0], JwtHeader.class);
            if (header == null || !"JWT".equals(header.getTokenType())) {
                this.log("Not a JWT token");
                return null;
            }

            if (!this.isAlgorithmAllowed(header.getAlgorithm())) {
                this.log(header.getAlgorithm() + " algorithm is not allowed");
                return null;
            }

            byte[] s = this.getValidateSecret(header, secret);
            if (s == null) {
                this.log("Unable to locate token secret");
                return null;
            }

            String tokenData = encoded.substring(0, encoded.lastIndexOf('.'));
            String expected = encoded.substring(encoded.lastIndexOf('.') + 1);
            if (!header.getAlgorithm().isSignatureValid(s, tokenData.getBytes(StandardCharsets.UTF_8), expected)) {
                this.log("Token signature is not valid");
                return null;
            }

            JwtPayload payload = this.fromBase64Json(parts[1], JwtPayload.class);

            Jwt t = new Jwt();
            t.setHeader(header);
            t.setPayload(payload);
            t.setSignature(parts[2]);

            String aud = audience == null ? this.getAudience() : audience;
            if (!t.validate(aud, this.getIssuers())) {
                this.log("Token failed data validation");
                return null;
            }

            return t;
        } catch (RuntimeException ex) {
            /*
             * Most commonly a parsing error in the Base64 String, in any case the token is
             * not valid.
             */
            this.log("Error validating token", ex);
            return null;
        }
    }

    protected String[] parseToken(String encoded) {
        if (encoded == null) {
            return null;
        }

        String[] parts = encoded.split("\\.");
        if (parts.length != 3) {
            return null;
        }

        for (String part : parts) {
            if (Util.isBlank(part)) {
                return null;
            }
        }

        return parts;
    }

    protected byte[] getSignSecret(JwtHeader header, byte[] defaultSecret) {
        return defaultSecret;
    }

    protected byte[] getValidateSecret(JwtHeader header, byte[] defaultSecret) {
        return defaultSecret;
    }

    protected <T> T fromBase64Json(String json, Class<T> clazz) {
        return Util.fromBase64Json(json, clazz);
    }

    /**
     * This method will test the {@linkplain #isAlgorithmAllowed(Algorithm)} method
     * to check if both HMAC and key based algorithms are permitted and if so it
     * will throw an exception as this presents a security flaw that enables an
     * attacker to forge their own tokens. <br />
     * <br />
     * Caution: Detection is based on
     * {@linkplain io.github.lc.oss.commons.signing.Algorithms#hmacAlgorithms()} and
     * {@linkplain io.github.lc.oss.commons.signing.Algorithms#keyAlgorithms()}.
     * Custom algorithms that bypass those filtered sets will also bypass detection
     * here.
     */
    protected void assertNotMixedAlgorithms() {
        boolean hasHmac = false;
        boolean hasKey = false;
        for (Algorithm a : Algorithms.hmacAlgorithms()) {
            if (this.isAlgorithmAllowed(a)) {
                hasHmac = true;
                break;
            }
        }

        for (Algorithm a : Algorithms.keyAlgorithms()) {
            if (this.isAlgorithmAllowed(a)) {
                hasKey = true;
                break;
            }
        }

        if (hasHmac && hasKey) {
            throw new RuntimeException("Insecure configuration detected. JWT verification must never permit "
                    + "both HMAC and key based signatures at the same time.");
        }
    }
}
