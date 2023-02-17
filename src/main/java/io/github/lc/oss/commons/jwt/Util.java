package io.github.lc.oss.commons.jwt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;

public class Util {
    private static final ObjectReader JSON_READER = new ObjectMapper().reader();
    private static final ObjectWriter JSON_WRITER = new ObjectMapper().writer();

    public static String toJsonNoSignature(Jwt token) {
        return String.format("%s.%s", Util.toBase64Json(token.getHeader()), Util.toBase64Json(token.getPayload()));
    }

    public static String toJson(Jwt token) {
        return String.format("%s.%s.%s", Util.toBase64Json(token.getHeader()), Util.toBase64Json(token.getPayload()), token.getSignature());
    }

    public static <T> T fromBase64Json(String base64, Class<T> clazz) {
        return Util.fromJson(Util.fromBase64(base64), clazz);
    }

    public static boolean isBlank(Object o) {
        if (o == null) {
            return true;
        }

        if (o instanceof String) {
            return ((String) o).trim().equals("");
        }

        if (o instanceof Collection) {
            return ((Collection<?>) o).isEmpty();
        }

        return false;
    }

    public static String toBase64(String data) {
        return new String(java.util.Base64.getEncoder(). //
                withoutPadding(). //
                encode(data.trim().getBytes(StandardCharsets.UTF_8)), //
                StandardCharsets.UTF_8);
    }

    public static String fromBase64(String data) {
        return new String(java.util.Base64.getDecoder(). //
                decode(data.trim()), //
                StandardCharsets.UTF_8);
    }

    public static String toBase64Json(AbstractJwtMap map) {
        return Util.toBase64(Util.toJson(map));
    }

    public static String toJson(AbstractJwtMap map) {
        try {
            return Util.JSON_WRITER.writeValueAsString(map);
        } catch (Exception ex) {
            throw new RuntimeException("Error serializing object.", ex);
        }
    }

    public static <T> T fromJson(String json, Class<T> clazz) {
        try {
            return Util.JSON_READER.readValue(json, clazz);
        } catch (IOException ex) {
            throw new RuntimeException("Error deserialzing object.", ex);
        }
    }

    private Util() {
    }
}
