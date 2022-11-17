package com.github.lc.oss.commons.jwt;

import java.util.Set;

import com.github.lc.oss.commons.signing.Algorithm;

public class Jwt {
    /**
     * Number of Seconds "in the future" a JWT is allowed to be Issued At or Not
     * Before and still considered valid. This is account for clock skew between
     * systems.
     */
    private static final long TOLERANCE = 5;

    private JwtHeader header = new JwtHeader();
    private JwtPayload payload = new JwtPayload();
    private String signature;

    public Jwt() {
    }

    public boolean validate(String audience, Set<String> issuers) {
        if (Util.isBlank(this.header) || //
                Util.isBlank(this.payload) || //
                Util.isBlank(audience) || //
                Util.isBlank(issuers)) //
        {
            return false;
        }

        String tokenType = this.header.getTokenType();
        if (!"JWT".equals(tokenType)) {
            return false;
        }

        if (this.header.getAlgorithm() == null) {
            return false;
        }

        Long expires = this.payload.getExpiration();
        Long notBefore = this.payload.getNotBefore();
        Long issuedAt = this.payload.getIssuedAt();
        if (expires == null || notBefore == null || issuedAt == null) {
            return false;
        }

        notBefore = notBefore - Jwt.TOLERANCE;
        issuedAt = issuedAt - Jwt.TOLERANCE;

        long now = System.currentTimeMillis() / 1000;
        if (expires <= now || notBefore > now || issuedAt > now) {
            return false;
        }

        if (Util.isBlank(this.getTokenId())) {
            return false;
        }

        if (Util.isBlank(this.payload.getSubject())) {
            return false;
        }

        if (!issuers.contains(this.payload.getIssuer())) {
            return false;
        }

        Set<String> allowedAudience = this.payload.getAudience();
        if (allowedAudience == null || !allowedAudience.contains(audience)) {
            return false;
        }

        return true;
    }

    public JwtHeader getHeader() {
        return this.header;
    }

    public void setHeader(JwtHeader header) {
        this.header = header;
    }

    public JwtPayload getPayload() {
        return this.payload;
    }

    public void setPayload(JwtPayload payload) {
        this.payload = payload;
    }

    public String getSignature() {
        return this.signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getKeyId() {
        return this.getHeader().getKeyId();
    }

    public Algorithm getAlgorithm() {
        if (this.getHeader() == null) {
            return null;
        }

        return this.getHeader().getAlgorithm();
    }

    public Set<String> getAudience() {
        return this.getPayload().getAudience();
    }

    public Long getIssuedAt() {
        return this.getPayload().getIssuedAt();
    }

    public String getIssuer() {
        return this.getPayload().getIssuer();
    }

    public Long getExpiration() {
        return this.getPayload().getExpiration();
    }

    public Long getExpirationMillis() {
        return this.getPayload().getExpirationMillis();
    }

    public void setExpirationMillis(long millis) {
        this.getPayload().setExpirationMillis(millis);
    }

    public String getSubject() {
        return this.getPayload().getSubject();
    }

    public String getTokenId() {
        return this.getPayload().getTokenId();
    }
}
