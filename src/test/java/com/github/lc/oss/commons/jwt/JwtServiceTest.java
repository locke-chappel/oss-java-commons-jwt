package com.github.lc.oss.commons.jwt;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.github.lc.oss.commons.signing.Algorithm;
import com.github.lc.oss.commons.signing.Algorithms;
import com.github.lc.oss.commons.testing.AbstractMockTest;

public class JwtServiceTest extends AbstractMockTest {
    private static class TestClass extends JwtService {
        private Clock clock = Mockito.mock(Clock.class);

        @Override
        public boolean isAlgorithmAllowed(Algorithm alg) {
            if (alg == null) {
                return false;
            }
            return Algorithms.has(alg.getId());
        }

        @Override
        public Set<String> getIssuers() {
            return new HashSet<>(Arrays.asList("junit-ca"));
        }

        @Override
        public String getAudience() {
            return "junit-app";
        }

        @Override
        protected byte[] getSignSecret(JwtHeader header, byte[] defaultSecret) {
            return "JWT-Secrets-Must-Be-At-Least-64-Characters-Long-To-Support-512-bit-HMACs".getBytes();
        }

        @Override
        protected byte[] getValidateSecret(JwtHeader header, byte[] defaultSecret) {
            return this.getSignSecret(header, defaultSecret);
        }

        @Override
        protected long now() {
            return this.clock.instant().toEpochMilli();
        }

        public Clock getClock() {
            return this.clock;
        }
    }

    @Test
    public void test_invalidate_null() {
        JwtService service = new TestClass();

        service.invalidate(null);
        service.invalidate(null, 1);
    }

    @Test
    public void test_invalidate_negativeExpiration() {
        JwtService service = new TestClass();

        try {
            service.invalidate("sig", -1);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Expiration must be positive number but was -1", ex.getMessage());
        }
    }

    @Test
    public void test_invalidate_signature() {
        JwtService service = new TestClass();

        Assertions.assertFalse(service.isRevoked("sig"));

        service.invalidate("sig", 1);

        Assertions.assertTrue(service.isRevoked("sig"));
    }

    @Test
    public void test_invalidate_token() {
        JwtService service = new TestClass();

        Jwt token = new Jwt();
        token.setExpirationMillis(System.currentTimeMillis() + 1000);
        token.setSignature("sig");

        Assertions.assertFalse(service.isRevoked("sig"));
        Assertions.assertFalse(service.isRevoked(token));

        service.invalidate(token);

        Assertions.assertTrue(service.isRevoked("sig"));
        Assertions.assertTrue(service.isRevoked(token));
    }

    @Test
    public void test_issue_missingAlgorithm() {
        JwtService service = new TestClass();

        try {
            service.issue(null, System.currentTimeMillis() + 1, System.currentTimeMillis(), "junit", "junit-ca", "junit-app");
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("All parameters are required", ex.getMessage());
        }
    }

    @Test
    public void test_issue_missingExpiration() {
        JwtService service = new TestClass();

        try {
            service.issue(Algorithms.HS256, null, System.currentTimeMillis(), "junit", "junit-ca", "junit-app");
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("All parameters are required", ex.getMessage());
        }
    }

    @Test
    public void test_issue_missingSubject() {
        JwtService service = new TestClass();

        try {
            service.issue(Algorithms.HS256, System.currentTimeMillis() + 1, System.currentTimeMillis(), null, "junit-ca", "junit-app");
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("All parameters are required", ex.getMessage());
        }
    }

    @Test
    public void test_issue_missingIssuer() {
        JwtService service = new TestClass();

        try {
            service.issue(Algorithms.HS256, System.currentTimeMillis() + 1, System.currentTimeMillis(), "junit", null, "junit-app");
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("All parameters are required", ex.getMessage());
        }
    }

    @Test
    public void test_issue_missingAudience() {
        JwtService service = new TestClass();

        try {
            service.issue(Algorithms.HS256, System.currentTimeMillis() + 1, System.currentTimeMillis(), "junit", "junit-ca", null);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("All parameters are required", ex.getMessage());
        }
    }

    @Test
    public void test_issue_expired() {
        JwtService service = new TestClass();

        try {
            service.issue(Algorithms.HS256, System.currentTimeMillis(), System.currentTimeMillis(), "junit", "junit-ca", "junit-app");
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Expiration must be in the future", ex.getMessage());
        }
    }

    @Test
    public void test_issue_expiresBeforeValid() {
        JwtService service = new TestClass();

        try {
            service.issue(Algorithms.HS256, System.currentTimeMillis() + 1000, System.currentTimeMillis() + 2000, "junit", "junit-ca", "junit-app");
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("'Not Before' cannot come after 'expires'", ex.getMessage());
        }
    }

    @Test
    public void test_issue_valid_defaults() {
        JwtService service = new TestClass();

        long now = System.currentTimeMillis();
        Jwt result = service.issue(Algorithms.HS256, now + 3000, "junit", "junit-ca", "junit-app");
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.validate("junit-app", new HashSet<>(Arrays.asList("junit-ca"))));
        Assertions.assertSame(Algorithms.HS256, result.getAlgorithm());
        Assertions.assertEquals("junit", result.getSubject());
        Assertions.assertEquals("junit-ca", result.getPayload().getIssuer());
        Set<String> audience = result.getAudience();
        Assertions.assertNotNull(audience);
        Assertions.assertEquals(1, audience.size());
        Assertions.assertTrue(audience.contains("junit-app"));
        Assertions.assertEquals((now + 3000) / 1000, result.getExpiration());
        Assertions.assertTrue(now / 1000 <= result.getPayload().getNotBefore());
        Assertions.assertTrue(now / 1000 + 1 >= result.getPayload().getNotBefore());
    }

    @Test
    public void test_issue_valid_defaults_v2() {
        JwtService service = new TestClass();

        long now = System.currentTimeMillis();
        Jwt result = service.issue(Algorithms.HS256, now + 3000, null, "junit", "junit-ca", "junit-app");
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.validate("junit-app", new HashSet<>(Arrays.asList("junit-ca"))));
        Assertions.assertSame(Algorithms.HS256, result.getAlgorithm());
        Assertions.assertEquals("junit", result.getSubject());
        Assertions.assertEquals("junit-ca", result.getPayload().getIssuer());
        Set<String> audience = result.getAudience();
        Assertions.assertNotNull(audience);
        Assertions.assertEquals(1, audience.size());
        Assertions.assertTrue(audience.contains("junit-app"));
        Assertions.assertEquals((now + 3000) / 1000, result.getExpiration());
        Assertions.assertTrue(now / 1000 <= result.getPayload().getNotBefore());
        Assertions.assertTrue(now / 1000 + 1 >= result.getPayload().getNotBefore());
    }

    @Test
    public void test_issue_valid_specificValues() {
        JwtService service = new TestClass();

        long now = System.currentTimeMillis();
        Jwt result = service.issue(Algorithms.HS256, now + 10000, now + 3000, "junit", "junit-ca", "junit-app");
        Assertions.assertNotNull(result);
        Assertions.assertSame(Algorithms.HS256, result.getAlgorithm());
        Assertions.assertEquals("junit", result.getSubject());
        Assertions.assertEquals("junit-ca", result.getPayload().getIssuer());
        Set<String> audience = result.getAudience();
        Assertions.assertNotNull(audience);
        Assertions.assertEquals(1, audience.size());
        Assertions.assertTrue(audience.contains("junit-app"));
        Assertions.assertEquals((now + 10000) / 1000, result.getExpiration());
        Assertions.assertEquals((now + 3000) / 1000, result.getPayload().getNotBefore());
    }

    @Test
    public void test_signAndEcnode_nullSecret() {
        JwtService service = new TestClass() {
            @Override
            protected byte[] getSignSecret(JwtHeader header, byte[] defaultSecret) {
                return null;
            }
        };

        Jwt jwt = new Jwt();

        try {
            service.signAndEncode(jwt);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Secret cannot be null", ex.getMessage());
        }
    }

    @Test
    public void test_signAndEcnode() {
        JwtService service = new TestClass();

        Jwt jwt = service.issue(Algorithms.HS256, System.currentTimeMillis() + 100000, "junit", "junit-ca", "junit-app");

        String result = service.signAndEncode(jwt);
        Assertions.assertNotNull(result);

        Jwt jwt2 = service.validate(result);
        Assertions.assertEquals(jwt.getTokenId(), jwt2.getTokenId());
        Assertions.assertEquals(jwt.getSignature(), jwt2.getSignature());
        String result2 = service.signAndEncode(jwt2);
        Assertions.assertEquals(result, result2);
    }

    @Test
    public void test_signAndEcnode_specifyAudience() {
        JwtService service = new TestClass();

        Jwt jwt = service.issue(Algorithms.HS256, System.currentTimeMillis() + 100000, "junit", "junit-ca", "junit-app");

        String result = service.signAndEncode(jwt);
        Assertions.assertNotNull(result);

        Jwt jwt2 = service.validate(result, jwt.getAudience().iterator().next());
        Assertions.assertEquals(jwt.getTokenId(), jwt2.getTokenId());
        Assertions.assertEquals(jwt.getSignature(), jwt2.getSignature());
        String result2 = service.signAndEncode(jwt2);
        Assertions.assertEquals(result, result2);

        // wrong audience
        Jwt jwt3 = service.validate(result, jwt.getAudience().iterator().next() + "-junk");
        Assertions.assertNull(jwt3);
    }

    @Test
    public void test_validate_parseTokenError() {
        JwtService service = new TestClass();

        Jwt result = service.validate(null);
        Assertions.assertNull(result);

        result = service.validate("no-t.valid-base64.str-ing");
        Assertions.assertNull(result);
    }

    @Test
    public void test_validate_isRevoked() {
        JwtService service = new TestClass();

        Jwt jwt = new Jwt();
        jwt.setSignature("sig");
        jwt.setExpirationMillis(System.currentTimeMillis() + 1000);
        service.invalidate(jwt);

        Jwt result = service.validate(Util.toJson(jwt));
        Assertions.assertNull(result);
    }

    @Test
    public void test_validate_badTokenType() {
        JwtService service = new TestClass();

        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "junk");

        Jwt result = service.validate(Util.toJson(jwt));
        Assertions.assertNull(result);
    }

    @Test
    public void test_validate_badAlgoritm() {
        JwtService service = new TestClass();

        // null
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().put(JwtHeader.Keys.Algorithm, null);

        Jwt result = service.validate(Util.toJson(jwt));
        Assertions.assertNull(result);

        // none
        jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(new Algorithm() {
            @Override
            public String getSignature(byte[] secret, byte[] data) {
                return null;
            }

            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, String signature) {
                return false;
            }

            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
                return false;
            }

            @Override
            public String getId() {
                return "none";
            }

            @Override
            public int getMinBitLength() {
                return 0;
            }

            @Override
            public String getSignature(String secret, String data) {
                return null;
            }

            @Override
            public boolean isSignatureValid(String secret, String data, String signature) {
                return false;
            }
        });

        result = service.validate(Util.toJson(jwt));
        Assertions.assertNull(result);

        // unknown
        jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(new Algorithm() {
            @Override
            public String getSignature(byte[] secret, byte[] data) {
                return null;
            }

            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, String signature) {
                return false;
            }

            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
                return false;
            }

            @Override
            public String getId() {
                return "HS128";
            }

            @Override
            public int getMinBitLength() {
                return 0;
            }

            @Override
            public String getSignature(String secret, String data) {
                return null;
            }

            @Override
            public boolean isSignatureValid(String secret, String data, String signature) {
                return false;
            }
        });

        result = service.validate(Util.toJson(jwt));
        Assertions.assertNull(result);
    }

    @Test
    public void test_validate_noSecret() {
        JwtService service = new TestClass() {
            @Override
            protected byte[] getSignSecret(JwtHeader header, byte[] defaultSecret) {
                return null;
            }
        };

        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS512);

        Jwt result = service.validate(Util.toJson(jwt));
        Assertions.assertNull(result);
    }

    @Test
    public void test_validate_badSignature() {
        JwtService service = new TestClass();

        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS512);

        Jwt result = service.validate(Util.toJson(jwt));
        Assertions.assertNull(result);
    }

    @Test
    public void test_validate_invalidToken() {
        JwtService service = new TestClass();

        Jwt jwt = service.issue(Algorithms.HS256, System.currentTimeMillis() + 100000, "junit", "junit-ca2", "junit-app2");

        Jwt result = service.validate(service.signAndEncode(jwt));
        Assertions.assertNull(result);
    }

    @Test
    public void test_getSignSecret() {
        JwtService service = new JwtService() {
            @Override
            public boolean isAlgorithmAllowed(Algorithm alg) {
                return false;
            }

            @Override
            public Set<String> getIssuers() {
                return null;
            }

            @Override
            public String getAudience() {
                return null;
            }

            @Override
            protected long now() {
                return 0;
            }
        };

        final byte[] secret = { 0x00 };

        byte[] result = service.getSignSecret(null, secret);
        Assertions.assertSame(secret, result);
    }

    @Test
    public void test_getValidateSecret() {
        JwtService service = new JwtService() {
            @Override
            public boolean isAlgorithmAllowed(Algorithm alg) {
                return false;
            }

            @Override
            public Set<String> getIssuers() {
                return null;
            }

            @Override
            public String getAudience() {
                return null;
            }

            @Override
            protected long now() {
                return 0;
            }
        };

        final byte[] secret = { 0x00 };

        byte[] result = service.getValidateSecret(null, secret);
        Assertions.assertSame(secret, result);
    }

    @Test
    public void test_parseToken() {
        JwtService service = new TestClass();

        String[] result = service.parseToken(null);
        Assertions.assertNull(result);

        result = service.parseToken("");
        Assertions.assertNull(result);

        result = service.parseToken(" \t \r \n \t ");
        Assertions.assertNull(result);

        result = service.parseToken("a.b");
        Assertions.assertNull(result);

        result = service.parseToken("a.b.c.d");
        Assertions.assertNull(result);

        result = service.parseToken("..");
        Assertions.assertNull(result);

        result = service.parseToken("a..b");
        Assertions.assertNull(result);

        result = service.parseToken("a.b.c");
        Assertions.assertNotNull(result);
        Assertions.assertEquals(3, result.length);
        Assertions.assertEquals("a", result[0]);
        Assertions.assertEquals("b", result[1]);
        Assertions.assertEquals("c", result[2]);
    }

    @Test
    public void test_refresh() {
        TestClass service = new TestClass();

        Mockito.when(service.getClock().instant()).thenReturn(Instant.now());

        final Jwt oldToken = new Jwt();
        oldToken.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        oldToken.setExpirationMillis(System.currentTimeMillis());
        oldToken.getPayload().setTokenId("jwtId");

        final String oldId = oldToken.getTokenId();
        final long oldExpiration = oldToken.getExpiration();
        final long oldIssuedAt = oldToken.getIssuedAt();

        Jwt newToken = service.refresh(oldToken, 10000, 1000);
        Assertions.assertNotEquals(oldId, newToken.getTokenId());
        Assertions.assertNotEquals(oldExpiration, newToken.getExpiration());
        Assertions.assertEquals(oldIssuedAt, newToken.getIssuedAt());
    }

    @Test
    public void test_refresh_maxLimit() {
        TestClass service = new TestClass();

        Mockito.when(service.getClock().instant()).thenReturn(Instant.now());

        final Jwt oldToken = new Jwt();
        oldToken.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        oldToken.setExpirationMillis(System.currentTimeMillis());
        oldToken.getPayload().setTokenId("jwtId");

        final String oldId = oldToken.getTokenId();
        final long oldExpiration = oldToken.getExpiration();
        final long oldIssuedAt = oldToken.getIssuedAt();

        Jwt newToken = service.refresh(oldToken, 10000, 20000);
        Assertions.assertNotEquals(oldId, newToken.getTokenId());
        Assertions.assertNotEquals(oldExpiration, newToken.getExpiration());
        Assertions.assertEquals(oldIssuedAt, newToken.getIssuedAt());
    }
}
