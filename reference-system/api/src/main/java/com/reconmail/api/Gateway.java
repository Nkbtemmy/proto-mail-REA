package com.reconmail.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * The API gateway: a single public port that reverse-proxies by path prefix to the
 * three backend microservices ({@code /api/v1/auth-server/*} → auth,
 * {@code /api/v1/key-server/*} → keys, {@code /api/v1/mail-server/*} → mail), passing
 * the path through unchanged. This is the one address clients talk to.
 */
public final class Gateway {

    private final HttpServer server;
    private final HttpClient http = HttpClient.newHttpClient();
    private final String authUrl;
    private final String keyUrl;
    private final String mailUrl;

    public Gateway(int port, String authUrl, String keyUrl, String mailUrl) throws Exception {
        this.authUrl = authUrl;
        this.keyUrl = keyUrl;
        this.mailUrl = mailUrl;
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.createContext("/", this::proxy);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    private void proxy(HttpExchange ex) {
        try {
            String path = ex.getRequestURI().getRawPath();
            String query = ex.getRequestURI().getRawQuery();
            String base = ApiPaths.isUnder(path, ApiPaths.AUTH) ? authUrl
                    : ApiPaths.isUnder(path, ApiPaths.KEYS) ? keyUrl
                    : ApiPaths.isUnder(path, ApiPaths.MAIL) ? mailUrl : null;
            if (base == null) {
                Http.error(ex, 404, "no backend for " + path + " (services live under "
                        + ApiPaths.AUTH + ", " + ApiPaths.KEYS + " and " + ApiPaths.MAIL + ")");
                return;
            }
            byte[] body = ex.getRequestBody().readAllBytes();
            String target = base + path + (query != null ? "?" + query : "");
            HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(target));
            String contentType = ex.getRequestHeaders().getFirst("Content-Type");
            if (contentType != null) {
                rb.header("Content-Type", contentType);
            }
            if ("GET".equals(ex.getRequestMethod())) {
                rb.GET();
            } else {
                rb.method(ex.getRequestMethod(), HttpRequest.BodyPublishers.ofByteArray(body));
            }
            HttpResponse<byte[]> resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofByteArray());
            byte[] out = resp.body();
            ex.getResponseHeaders().set("Content-Type",
                    resp.headers().firstValue("Content-Type").orElse("application/json"));
            ex.sendResponseHeaders(resp.statusCode(), out.length == 0 ? -1 : out.length);
            try (OutputStream os = ex.getResponseBody()) {
                if (out.length > 0) {
                    os.write(out);
                }
            }
        } catch (Exception e) {
            Http.error(ex, 502, "gateway error: " + e.getMessage());
        } finally {
            ex.close();
        }
    }
}
