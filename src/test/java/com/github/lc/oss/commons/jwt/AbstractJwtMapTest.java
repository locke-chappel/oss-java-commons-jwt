package com.github.lc.oss.commons.jwt;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lc.oss.commons.testing.AbstractMockTest;

public class AbstractJwtMapTest extends AbstractMockTest {
    private static class TestMap extends AbstractJwtMap {
        private static final long serialVersionUID = 3251835908172256971L;
    }

    @Test
    public void test_getString() {
        AbstractJwtMap map = new TestMap();

        map.put("a", "A");
        map.put("b", " B \t \r \n ");
        map.put("1", 1);
        map.put("", "");
        map.put("null", null);

        Assertions.assertEquals("A", map.getString("a", false));
        Assertions.assertEquals("A", map.getString("a", true));

        Assertions.assertEquals(" B \t \r \n ", map.getString("b", false));
        Assertions.assertEquals("B", map.getString("b", true));

        Assertions.assertNull(map.getString("1", false));
        Assertions.assertNull(map.getString("1", true));

        Assertions.assertEquals("", map.getString("", false));
        Assertions.assertNull(map.getString("", true));

        Assertions.assertNull(map.getString("null", false));
        Assertions.assertNull(map.getString("null", true));

        // default trims
        Assertions.assertEquals("B", map.getString("b"));
    }

    @Test
    public void test_getSet() {
        AbstractJwtMap map = new TestMap();

        final Set<Integer> set = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(1, 2, 3)));

        map.put("a", "A");
        map.put("b", Arrays.asList("B"));
        map.put("c", set);
        map.put("null", null);
        map.put("", "");
        map.put("blank", " ");

        // no promotion
        Assertions.assertNull(map.getSet("a", false));
        Assertions.assertNull(map.getSet("null", false));
        Assertions.assertNull(map.getSet("", false));
        Assertions.assertNull(map.getSet("blank", false));

        Set<?> result = map.getSet("b", false);
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains("B"));

        result = map.getSet("c", false);
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains(1));
        Assertions.assertTrue(result.contains(2));

        // with promotion
        result = map.getSet("a", true);
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains("A"));

        result = map.getSet("b", true);
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains("B"));

        result = map.getSet("c", true);
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains(1));
        Assertions.assertTrue(result.contains(2));

        result = map.getSet("", true);
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains(""));

        result = map.getSet("blank", true);
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains(" "));

        Assertions.assertNull(map.getSet("null", true));

        // default promotes
        result = map.getSet("a");
        Assertions.assertNotNull(result);
        Assertions.assertTrue(result.contains("A"));
    }

    @Test
    public void test_getLong() {
        AbstractJwtMap map = new TestMap();

        map.put("a", "A");
        map.put("b", " B \t \r \n ");
        map.put("-1", -1);
        map.put("0", 0);
        map.put("1", 1);
        map.put("", "");
        map.put("null", null);

        // include negative
        Assertions.assertNull(map.getLong("a", false));
        Assertions.assertNull(map.getLong("b", false));
        Assertions.assertNull(map.getLong("", false));
        Assertions.assertNull(map.getLong("null", false));
        Assertions.assertEquals(-1, map.getLong("-1", false));
        Assertions.assertEquals(0, map.getLong("0", false));
        Assertions.assertEquals(1, map.getLong("1", false));

        // positive only
        Assertions.assertNull(map.getLong("a", true));
        Assertions.assertNull(map.getLong("b", true));
        Assertions.assertNull(map.getLong("", true));
        Assertions.assertNull(map.getLong("null", true));
        Assertions.assertNull(map.getLong("-1", true));
        Assertions.assertEquals(0, map.getLong("0", true));
        Assertions.assertEquals(1, map.getLong("1", true));

        // default positive only
        Assertions.assertNull(map.getLong("-1"));
        Assertions.assertEquals(0, map.getLong("0"));
        Assertions.assertEquals(1, map.getLong("1"));
    }
}
