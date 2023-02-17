package io.github.lc.oss.commons.jwt;

public interface User {
    String getId();

    default String getCacheId() {
        return this.getId();
    }
}
