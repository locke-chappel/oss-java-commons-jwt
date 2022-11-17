package com.github.lc.oss.commons.jwt;

import com.github.lc.oss.commons.util.SimpleTimedCache;

public class DefaultUserCache<T extends User> extends SimpleTimedCache<T> implements UserCache<T> {
    public DefaultUserCache() {
        super(0);
    }

    @Override
    public void add(T user, long expires) {
        this.add(user, user.getCacheId(), expires);
    }

    @Override
    public void add(T user, String key, long expires) {
        super.add(key, user, expires);
    }
}
