package com.github.lc.oss.commons.jwt;

import com.github.lc.oss.commons.signing.Algorithm;
import com.github.lc.oss.commons.signing.Algorithms;

public class JwtHeader extends AbstractJwtMap {
    private static final long serialVersionUID = 5967113948485997631L;

    public static class Keys {
        public static final String TokenType = "typ";
        public static final String ContentType = "cty";
        public static final String Algorithm = "alg";
        public static final String KeyId = "kid";
        public static final String X509CertificateChain = "x5c";
        public static final String X509CertificateChainUrl = "x5u";
        public static final String Critical = "crit";

        private Keys() {
        }
    }

    public String getTokenType() {
        return this.getString(Keys.TokenType);
    }

    public String getKeyId() {
        return this.getString(Keys.KeyId);
    }

    public void setKeyId(String keyId) {
        this.put(Keys.KeyId, keyId);
    }

    public Algorithm getAlgorithm() {
        return Algorithms.get(this.getString(Keys.Algorithm));
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.put(Keys.Algorithm, algorithm.getId());
    }
}
