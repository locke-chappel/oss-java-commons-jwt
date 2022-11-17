package com.github.lc.oss.commons.jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class JwtPayload extends AbstractJwtMap {
    private static final long serialVersionUID = 8801866891768624394L;

    public static class Keys {
        public static final String Issuer = "iss";
        public static final String Subject = "sub";
        public static final String Audience = "aud";
        public static final String ExpirationDate = "exp";
        public static final String NotBefore = "nbf";
        public static final String IssuedAt = "iat";
        public static final String JwtId = "jti";

        public static final String DisplayName = "x-disp";
        public static final String Permissions = "x-perm";

        private Keys() {
        }
    }

    public Set<String> getAudience() {
        return this.getSet(Keys.Audience);
    }

    public void setAudience(String audience) {
        this.put(Keys.Audience, audience);
    }

    public void setAudience(Collection<String> audience) {
        this.put(Keys.Audience, audience);
    }

    public Long getExpiration() {
        return this.getLong(Keys.ExpirationDate);
    }

    public Long getExpirationMillis() {
        if (this.getExpiration() == null) {
            return null;
        }
        return this.getExpiration() * 1000;
    }

    public void setExpiration(long seconds) {
        this.put(Keys.ExpirationDate, seconds);
    }

    public void setExpirationMillis(long millis) {
        this.put(Keys.ExpirationDate, millis / 1000);
    }

    public Long getIssuedAt() {
        return this.getLong(Keys.IssuedAt);
    }

    public void setIssuedAt(long seconds) {
        this.put(Keys.IssuedAt, seconds);
    }

    public void setIssuedAtMillis(long millis) {
        this.put(Keys.IssuedAt, millis / 1000);
    }

    public Long getNotBefore() {
        return this.getLong(Keys.NotBefore);
    }

    public void setNotBefore(long seconds) {
        this.put(Keys.NotBefore, seconds);
    }

    public void setNotBeforeMillis(long millis) {
        this.put(Keys.NotBefore, millis / 1000);
    }

    public String getIssuer() {
        return this.getString(Keys.Issuer);
    }

    public void setIssuer(String issuer) {
        this.put(Keys.Issuer, issuer);
    }

    public String getSubject() {
        return this.getString(Keys.Subject);
    }

    public void setSubject(String subject) {
        this.put(Keys.Subject, subject);
    }

    public String getTokenId() {
        return this.getString(Keys.JwtId);
    }

    public void setTokenId(String tokenId) {
        this.put(Keys.JwtId, tokenId);
    }

    public String getDisplayName() {
        return this.getString(Keys.DisplayName);
    }

    public void setDisplayName(String displayName) {
        this.put(Keys.DisplayName, displayName);
    }

    public boolean hasPermission(String audience, String permission) {
        Collection<String> permissions = this.getPermissions(audience);
        if (permissions == null) {
            return false;
        }
        return permissions.contains(permission);
    }

    public Collection<String> getPermissions(String audience) {
        Map<String, Collection<String>> permissions = this.getPermissions();
        if (permissions == null) {
            return null;
        }
        return permissions.get(audience);
    }

    public Map<String, Collection<String>> getPermissions() {
        return this.getMap(Keys.Permissions);
    }

    public void setPermissions(String audience, String permission) {
        this.setPermissions(audience, Arrays.asList(permission));
    }

    public void setPermissions(String audience, Collection<String> permissions) {
        Map<String, Collection<String>> perms = this.getPermissions();
        if (perms == null) {
            perms = new HashMap<>();
            this.setPermissions(perms);
        }

        perms.put(audience, new HashSet<>(permissions));
    }

    public void setPermissions(Map<String, Collection<String>> permissions) {
        this.put(Keys.Permissions, permissions);
    }
}
