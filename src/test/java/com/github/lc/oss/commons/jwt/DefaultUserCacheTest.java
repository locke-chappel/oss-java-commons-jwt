package com.github.lc.oss.commons.jwt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lc.oss.commons.testing.AbstractMockTest;

public class DefaultUserCacheTest extends AbstractMockTest {
    private static class TestUser implements User {
        private final String id;

        public TestUser(String id) {
            this.id = id;
        }

        @Override
        public String getId() {
            return this.id;
        }
    }

    @Test
    public void test_get() {
        User user1 = new TestUser("a");
        User user2 = new TestUser("b");

        DefaultUserCache<User> cache = new DefaultUserCache<>();

        cache.add(user1, System.currentTimeMillis() - 1000);
        cache.add(user2, System.currentTimeMillis() + 1000);

        Assertions.assertNull(cache.get("a"));
        Assertions.assertSame(user2, cache.get("b"));
    }

    @Test
    public void test_getNonexistant() {
        DefaultUserCache<User> cache = new DefaultUserCache<>();

        Assertions.assertNull(cache.get("junk"));
    }
}
