package com.reconmail.api;

/** Reads configuration from environment variables with a fallback default. */
final class Env {

    private Env() {
    }

    static String get(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    static int getInt(String key, int fallback) {
        return Integer.parseInt(get(key, Integer.toString(fallback)));
    }
}
