package io.github.lc.oss.commons.jwt;

import java.util.HashMap;
import java.util.Map;

public class JwtRevocationList {
    private final Map<String, Long> map = new HashMap<>();

    public void revoke(Jwt token) {
        this.revoke(token.getSignature(), token.getExpiration() * 1000 + 10000);
    }

    public void revoke(String signature, long expiration) {
        this.map.put(signature, expiration);
    }

    public void clean() {
        final long now = System.currentTimeMillis();
        this.map.values().removeIf(i -> now >= i);
    }

    public boolean isRevoked(String signature) {
        return this.map.containsKey(signature);
    }
}
