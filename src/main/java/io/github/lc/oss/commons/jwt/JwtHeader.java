package io.github.lc.oss.commons.jwt;

import io.github.lc.oss.commons.signing.Algorithm;
import io.github.lc.oss.commons.signing.Algorithms;
import io.github.lc.oss.commons.signing.EddsaAlgorithm;

public class JwtHeader extends AbstractJwtMap {
    private static final long serialVersionUID = 5967113948485997631L;

    public static class Keys {
        public static final String TokenType = "typ";
        public static final String ContentType = "cty";
        public static final String Curve = "crv";
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
        String alg = this.getString(Keys.Algorithm);
        if (alg == null) {
            return null;
        }

        if (alg.trim().equals("EdDSA")) {
            return Algorithms.get(this.getString(Keys.Curve));
        }
        return Algorithms.get(alg);
    }

    public void setAlgorithm(Algorithm algorithm) {
        if (algorithm instanceof EddsaAlgorithm) {
            this.put(Keys.Algorithm, "EdDSA");
            this.put(Keys.Curve, algorithm.getId());
        } else {
            this.put(Keys.Algorithm, algorithm.getId());
        }
    }
}
