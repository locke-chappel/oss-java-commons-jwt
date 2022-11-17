package com.github.lc.oss.commons.jwt;

import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lc.oss.commons.testing.AbstractMockTest;

public class JwtRevocationListTest extends AbstractMockTest {
    @Test
    public void test_cleanExpired() {
        Jwt token1 = new Jwt();
        token1.setSignature("s");
        token1.setExpirationMillis(System.currentTimeMillis() - 100000);
        Jwt token2 = new Jwt();
        token2.setSignature("t");
        token2.setExpirationMillis(System.currentTimeMillis() + 100000);

        JwtRevocationList list = new JwtRevocationList();

        final Map<?, ?> map = this.getField("map", list);

        Assertions.assertNotNull(map);
        Assertions.assertTrue(map.isEmpty());

        list.revoke(token1);
        list.revoke(token2);

        Map<?, ?> map2 = this.getField("map", list);
        Assertions.assertSame(map, map2);
        Assertions.assertEquals(2, map.size());

        Assertions.assertTrue(list.isRevoked(token1.getSignature()));
        Assertions.assertTrue(list.isRevoked(token2.getSignature()));

        list.clean();

        map2 = this.getField("map", list);
        Assertions.assertSame(map, map2);
        Assertions.assertEquals(1, map.size());

        Assertions.assertFalse(list.isRevoked(token1.getSignature()));
        Assertions.assertTrue(list.isRevoked(token2.getSignature()));
    }
}
