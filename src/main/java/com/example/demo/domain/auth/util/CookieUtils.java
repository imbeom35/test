package com.example.demo.domain.auth.util;

import jakarta.servlet.http.*;
import lombok.SneakyThrows;

import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class CookieUtils {

    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return Optional.empty();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(name)) {
                return Optional.of(cookie);
            }
        }
        return Optional.empty();
    }

    public static void addCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(false);
        cookie.setMaxAge(maxAgeSeconds);
        // 필요시 cookie.setSecure(true); SameSite=None 설정은 서버/프록시에서 처리
        response.addCookie(cookie);
    }

    public static void addHttpOnlyCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAgeSeconds);
        response.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    public static void addSerializedCookie(HttpServletResponse response, String name, Serializable obj, int maxAgeSeconds) {
        String encoded = serialize(obj);
        addCookie(response, name, encoded, maxAgeSeconds);
    }

    public static <T> T deserialize(String cookieValue, Class<T> cls) {
        byte[] data = Base64.getUrlDecoder().decode(cookieValue);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object obj = ois.readObject();
            return cls.cast(obj);
        } catch (IOException | ClassNotFoundException e) {
            throw new IllegalArgumentException("Cookie deserialization failed", e);
        }
    }

    @SneakyThrows
    public static <T extends Serializable> String serialize(T obj) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
        }
        return Base64.getUrlEncoder().encodeToString(bos.toByteArray());
    }
}