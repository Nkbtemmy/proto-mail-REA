package com.reconmail.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

/** Shared JSON request/response plumbing for the (split) HTTP services. */
final class Http {

    static final ObjectMapper JSON = new ObjectMapper();

    /** The body of every error response. */
    record ApiError(String error) {}

    private Http() {
    }

    /** Binds {@code port} and mounts each router under its base path; any other path is a JSON 404. */
    static HttpServer serve(int port, Router... routers) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", ex -> {
            String path = ex.getRequestURI().getRawPath();
            for (Router router : routers) {
                if (ApiPaths.isUnder(path, router.base())) {
                    router.handle(ex);
                    return;
                }
            }
            try {
                error(ex, 404, "no route: " + ex.getRequestMethod() + " " + ex.getRequestURI().getPath());
            } finally {
                ex.close();
            }
        });
        return server;
    }

    static <T> T read(HttpExchange ex, Class<T> type) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return JSON.readValue(in, type);
        }
    }

    static void write(HttpExchange ex, int code, Object body) throws IOException {
        send(ex, code, "application/json", JSON.writeValueAsBytes(body));
    }

    static void send(HttpExchange ex, int code, String contentType, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(code, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    static void error(HttpExchange ex, int code, String message) {
        try {
            write(ex, code, new ApiError(message));
        } catch (IOException ignored) {
            // response already started
        }
    }
}
