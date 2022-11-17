package com.github.lc.oss.commons.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lc.oss.commons.signing.Algorithms;
import com.github.lc.oss.commons.testing.AbstractMockTest;

public class UtilTest extends AbstractMockTest {
    @Test
    public void test_isBlank() {
        Assertions.assertTrue(Util.isBlank(null));
        Assertions.assertTrue(Util.isBlank(""));
        Assertions.assertTrue(Util.isBlank(" \t \r \n \t "));
        Assertions.assertTrue(Util.isBlank(new ArrayList<>()));
        Assertions.assertTrue(Util.isBlank(new HashSet<>()));

        Assertions.assertFalse(Util.isBlank(new Object()));
        Assertions.assertFalse(Util.isBlank("a"));
        Assertions.assertFalse(Util.isBlank(" b "));
        Assertions.assertFalse(Util.isBlank(Arrays.asList("a")));
        Assertions.assertFalse(Util.isBlank(Arrays.asList("")));
    }

    @Test
    public void test_toJson_error() {
        Jwt token = new Jwt();
        token.getHeader().put("explosive", new Object() {
            @SuppressWarnings("unused")
            public String detonate() {
                throw new RuntimeException("Boom!");
            }
        });

        try {
            Util.toJson(token);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error serializing object.", ex.getMessage());
        }
    }

    @Test
    public void test_fromJson_error() {
        try {
            Util.fromBase64Json(Util.toBase64("junk"), JwtHeader.class);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error deserialzing object.", ex.getMessage());
        }
    }

    @Test
    public void test_toJson() {
        Jwt token = new Jwt();
        token.getHeader().setAlgorithm(Algorithms.HS256);
        token.getHeader().setKeyId("id-1");
        token.getPayload().setAudience("me");
        token.getPayload().put("empty", new HashSet<>());
        token.getPayload().put("set", new HashSet<>(Arrays.asList("a", "b", "c")));
        token.setSignature("sig");
        String result = Util.toJson(token);
        Assertions.assertNotNull(result);
        String[] parts = result.split("\\.");
        Assertions.assertEquals(3, parts.length);
        Assertions.assertEquals("eyJraWQiOiJpZC0xIiwiYWxnIjoiSFMyNTYifQ", parts[0]);
        Assertions.assertEquals("sig", parts[2]);

        JwtHeader header = Util.fromBase64Json(parts[0], JwtHeader.class);
        JwtPayload payload = Util.fromBase64Json(parts[1], JwtPayload.class);
        Assertions.assertEquals(Algorithms.HS256, header.getAlgorithm());
        Assertions.assertEquals("id-1", header.getKeyId());
        Assertions.assertEquals(1, payload.getAudience().size());
        Assertions.assertEquals("me", payload.getAudience().iterator().next());
        Set<String> set = payload.getSet("empty");
        Assertions.assertNotNull(payload.get("empty"));
        Assertions.assertTrue(set.isEmpty());
        set = payload.getSet("set");
        Assertions.assertNotNull(set);
        Assertions.assertEquals(3, set.size());
        Assertions.assertTrue(set.contains("a"));
        Assertions.assertTrue(set.contains("b"));
        Assertions.assertTrue(set.contains("c"));
    }

    @Test
    public void test_toJsonNoSignature() {
        Jwt token = new Jwt();
        token.getHeader().setAlgorithm(Algorithms.HS256);
        token.getHeader().setKeyId("id-1");
        token.getPayload().setAudience("me");
        String result = Util.toJsonNoSignature(token);
        Assertions.assertNotNull(result);
        String[] parts = result.split("\\.");
        Assertions.assertEquals(2, parts.length);
        Assertions.assertEquals("eyJraWQiOiJpZC0xIiwiYWxnIjoiSFMyNTYifQ", parts[0]);
    }
}
