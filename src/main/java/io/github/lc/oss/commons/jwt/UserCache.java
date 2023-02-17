package io.github.lc.oss.commons.jwt;

public interface UserCache<T> {
    void add(T user, long expires);

    void add(T user, String key, long expires);

    T get(String key);

    void clean();

    void clear();

    void remove(String key);
}
