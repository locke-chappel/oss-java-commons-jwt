package io.github.lc.oss.commons.jwt;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class AbstractJwtMap extends HashMap<String, Object> {
    private static final long serialVersionUID = -2604762012165449371L;

    @SuppressWarnings("unchecked")
    public <K, V> Map<K, V> getMap(String key) {
        Object value = this.get(key);
        if (value instanceof Map) {
            return (Map<K, V>) value;
        }
        return null;
    }

    public <T> Set<T> getSet(String key) {
        return this.getSet(key, true);
    }

    @SuppressWarnings("unchecked")
    public <T> Set<T> getSet(String key, boolean promoteToSet) {
        Object value = this.get(key);
        if (value instanceof Collection) {
            return new HashSet<>((Collection<T>) value);
        } else if (value != null && promoteToSet) {
            return new HashSet<>(Arrays.asList((T) value));
        }
        return null;
    }

    public String getString(String key) {
        return this.getString(key, true);
    }

    public String getString(String key, boolean trimToNull) {
        Object value = this.get(key);
        if (value instanceof String) {
            String s = (String) value;
            if (!trimToNull) {
                return s;
            }

            s = s.trim();
            if (s.equals("")) {
                return null;
            }
            return s;
        }
        return null;
    }

    public Long getLong(String key) {
        return this.getLong(key, true);
    }

    public Long getLong(String key, boolean positive) {
        Object value = this.get(key);
        if (value instanceof Number) {
            Long l = ((Number) value).longValue();
            if (!positive) {
                return l;
            }

            if (l < 0) {
                return null;
            }
            return l;
        }
        return null;
    }
}
