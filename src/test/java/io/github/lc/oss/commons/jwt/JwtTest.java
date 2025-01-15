package io.github.lc.oss.commons.jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.github.lc.oss.commons.signing.Algorithms;
import io.github.lc.oss.commons.testing.AbstractMockTest;

public class JwtTest extends AbstractMockTest {
    @Test
    public void test_validate_noData() {
        Jwt jwt = new Jwt();
        jwt.setHeader(null);
        jwt.setPayload(null);

        boolean result = jwt.validate(null, null);
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingHeader() {
        Jwt jwt = new Jwt();
        jwt.setHeader(null);

        Assertions.assertNull(jwt.getHeader());
        Assertions.assertNotNull(jwt.getPayload());

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingPayload() {
        Jwt jwt = new Jwt();
        jwt.setPayload(null);

        Assertions.assertNotNull(jwt.getHeader());
        Assertions.assertNull(jwt.getPayload());

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingAudiences() {
        Jwt jwt = new Jwt();

        Assertions.assertNotNull(jwt.getHeader());
        Assertions.assertNotNull(jwt.getPayload());

        boolean result = jwt.validate(null, new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingIssuers() {
        Jwt jwt = new Jwt();

        Assertions.assertNotNull(jwt.getHeader());
        Assertions.assertNotNull(jwt.getPayload());

        boolean result = jwt.validate("audience", null);
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_wrongTokenType() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "junk");

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingAlgorithm() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().put(JwtHeader.Keys.Algorithm, null);

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingExpires() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.getPayload().put(JwtPayload.Keys.ExpirationDate, null);

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingNotBefore() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.ED25519);
        jwt.setExpirationMillis(System.currentTimeMillis());
        jwt.getPayload().put(JwtPayload.Keys.NotBefore, null);

        Assertions.assertEquals(Algorithms.ED25519, jwt.getHeader().getAlgorithm());
        Assertions.assertEquals("EdDSA", jwt.getHeader().getString(JwtHeader.Keys.Algorithm, false));
        Assertions.assertEquals(Algorithms.ED25519.getId(), jwt.getHeader().getString(JwtHeader.Keys.Curve, false));

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingIssuedAt() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.ED448);
        jwt.setExpirationMillis(System.currentTimeMillis());
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().put(JwtPayload.Keys.IssuedAt, null);

        Assertions.assertEquals(Algorithms.ED448, jwt.getHeader().getAlgorithm());
        Assertions.assertEquals("EdDSA", jwt.getHeader().getString(JwtHeader.Keys.Algorithm, false));
        Assertions.assertEquals(Algorithms.ED448.getId(), jwt.getHeader().getString(JwtHeader.Keys.Curve, false));
        Assertions.assertNull(jwt.getIssuedAt());

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_expired() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.ES256);
        jwt.setExpirationMillis(System.currentTimeMillis() - 1);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());

        Assertions.assertNull(jwt.getHeader().getString(JwtHeader.Keys.Curve, false));

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_notYet() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_fromTheFuture() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis() + 10000);

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingTokenId() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        jwt.getPayload().setTokenId(null);

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingSubject() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject(null);

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingIssuer() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer(null);

        Assertions.assertNull(jwt.getIssuer());

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_untrustedIssuer() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer("junit");

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingAudience_empty() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer("is-a");
        jwt.getPayload().setAudience(new HashSet<>());

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_missingAudience_null() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer("is-a");
        jwt.getPayload().setAudience((Collection<String>) null);

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_wrongAudience() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer("is-a");
        jwt.getPayload().setAudience(Arrays.asList("junit"));

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_valid() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis());
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis());
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer("is-a");
        jwt.getPayload().setAudience("audience");

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertTrue(result);
    }

    @Test
    public void test_validate_valid_clockSkew() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis() + 5000);
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis() + 5000);
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer("is-a");
        jwt.getPayload().setAudience("audience");

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertTrue(result);
    }

    @Test
    public void test_validate_invalid_clockSkew_notBefore() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis() + 6000);
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis() + 4000);
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer("is-a");
        jwt.getPayload().setAudience("audience");

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_validate_invalid_clockSkew_issuedAt() {
        Jwt jwt = new Jwt();
        jwt.getHeader().put(JwtHeader.Keys.TokenType, "JWT");
        jwt.getHeader().setAlgorithm(Algorithms.HS256);
        jwt.setExpirationMillis(System.currentTimeMillis() + 10000);
        jwt.getPayload().setNotBeforeMillis(System.currentTimeMillis() + 4000);
        jwt.getPayload().setIssuedAtMillis(System.currentTimeMillis() + 6000);
        jwt.getPayload().setTokenId(UUID.randomUUID().toString());
        jwt.getPayload().setSubject("junit");
        jwt.getPayload().setIssuer("is-a");
        jwt.getPayload().setAudience("audience");

        boolean result = jwt.validate("audience", new HashSet<>(Arrays.asList("is-b", "is-a")));
        Assertions.assertFalse(result);
    }

    @Test
    public void test_keyId() {
        Jwt jwt = new Jwt();
        jwt.getHeader().setKeyId("k-id");

        Assertions.assertEquals("k-id", jwt.getKeyId());
    }

    @Test
    public void test_algorithm() {
        Jwt jwt = new Jwt();
        jwt.setHeader(null);

        Assertions.assertNull(jwt.getHeader());

        Assertions.assertNull(jwt.getAlgorithm());

        jwt = new Jwt();
        jwt.getHeader().setAlgorithm(Algorithms.HS512);

        Assertions.assertEquals(Algorithms.HS512, jwt.getAlgorithm());
    }

    @Test
    public void test_xFields() {
        Jwt jwt = new Jwt();

        Assertions.assertNull(jwt.getPayload().getDisplayName());
        Assertions.assertNull(jwt.getPayload().getPermissions());
        Assertions.assertNull(jwt.getPayload().getPermissions("a-1"));
        Assertions.assertFalse(jwt.getPayload().hasPermission("a-1", "perm"));
        Assertions.assertFalse(jwt.getPayload().hasPermission("junk", "perm"));

        jwt.getPayload().setDisplayName("name");
        jwt.getPayload().setPermissions("a-1", "perm");
        jwt.getPayload().setPermissions("a-2", Arrays.asList("perm", "another"));

        Assertions.assertTrue(jwt.getPayload().hasPermission("a-1", "perm"));
        Assertions.assertTrue(jwt.getPayload().hasPermission("a-2", "perm"));
        Assertions.assertTrue(jwt.getPayload().hasPermission("a-2", "another"));
        Assertions.assertFalse(jwt.getPayload().hasPermission("a-1", "junk"));
        Assertions.assertFalse(jwt.getPayload().hasPermission("junk", "perm"));

        Collection<String> set1 = jwt.getPayload().getPermissions("a-1");
        Assertions.assertEquals(1, set1.size());
        Assertions.assertTrue(set1.contains("perm"));

        Collection<String> set2 = jwt.getPayload().getPermissions("a-2");
        Assertions.assertEquals(2, set2.size());
        Assertions.assertTrue(set2.contains("perm"));
        Assertions.assertTrue(set2.contains("another"));

        Assertions.assertEquals("name", jwt.getPayload().getDisplayName());
        Map<String, Collection<String>> permissions = jwt.getPayload().getPermissions();
        Assertions.assertNotNull(permissions);
        Assertions.assertEquals(2, permissions.size());
        Assertions.assertTrue(permissions.containsKey("a-1"));
        Assertions.assertTrue(permissions.containsKey("a-2"));
        Collection<String> set = permissions.get("a-1");
        Assertions.assertEquals(1, set.size());
        Assertions.assertTrue(set.contains("perm"));
        Assertions.assertSame(set1, set);
    }

    @Test
    public void test_getExpirationMillis() {
        Jwt jwt = new Jwt();

        Assertions.assertNull(jwt.getExpiration());
        Assertions.assertNull(jwt.getExpirationMillis());

        jwt.setExpirationMillis(999999999);

        Assertions.assertEquals(999999, jwt.getExpiration());
        Assertions.assertEquals(999999000, jwt.getExpirationMillis());
    }
}
