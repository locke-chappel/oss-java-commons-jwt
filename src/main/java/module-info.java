module com.github.lc.oss.commons.jwt {
    requires transitive com.github.lc.oss.commons.signing;
    requires com.github.lc.oss.commons.util;

    requires com.fasterxml.jackson.databind;

    exports com.github.lc.oss.commons.jwt;
}
