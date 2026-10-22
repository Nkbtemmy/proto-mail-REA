package com.reconmail.api;

/**
 * The public URL layout: every service lives under {@code /api/v1/<service-name>},
 * whether it runs alone, behind the gateway, or inside the all-in-one server.
 */
final class ApiPaths {

    static final String V1 = "/api/v1";
    static final String AUTH = V1 + "/auth-server";
    static final String KEYS = V1 + "/key-server";
    static final String MAIL = V1 + "/mail-server";

    private ApiPaths() {
    }

    /** True if {@code path} is {@code base} itself or lies beneath it (segment-aware). */
    static boolean isUnder(String path, String base) {
        return path.equals(base) || path.startsWith(base + "/");
    }
}
