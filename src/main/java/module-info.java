module io.github.lc.oss.commons.jwt {
    requires transitive io.github.lc.oss.commons.signing;
    requires io.github.lc.oss.commons.util;

    requires com.fasterxml.jackson.databind;

    exports io.github.lc.oss.commons.jwt;
}
