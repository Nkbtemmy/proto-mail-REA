package com.reconmail.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

/**
 * One service's HTTP API under a base path (e.g. {@code /api/v1/auth-server}): a small
 * route table that both dispatches requests and describes them. The OpenAPI document
 * at {@code <base>/openapi.json} is generated from that same table, so the Swagger UI
 * at {@code <base>/docs} cannot drift from what the service actually serves.
 */
final class Router implements HttpHandler {

    /** Handles a matched request; {@code params} holds the decoded {@code {name}} path segments. */
    @FunctionalInterface
    interface Handler {
        void handle(HttpExchange ex, Map<String, String> params) throws Exception;
    }

    private static final String SWAGGER_UI = "META-INF/resources/webjars/swagger-ui/" + swaggerUiVersion() + "/";

    private final String base;
    private final String title;
    private final String description;
    private final List<Route> routes = new ArrayList<>();

    Router(String base, String title, String description) {
        this.base = base;
        this.title = title;
        this.description = description;
    }

    String base() {
        return base;
    }

    Route get(String template) {
        return new Route("GET", template);
    }

    Route post(String template) {
        return new Route("POST", template);
    }

    /** The {@code List<item>} type, for documenting a route that returns a JSON array. */
    static Type listOf(Class<?> item) {
        return new ParameterizedType() {
            @Override
            public Type[] getActualTypeArguments() {
                return new Type[]{item};
            }

            @Override
            public Type getRawType() {
                return List.class;
            }

            @Override
            public Type getOwnerType() {
                return null;
            }
        };
    }

    /** A route being declared: {@code router.post("/x").summary(..).body(..).returns(..).handle(..)}. */
    final class Route {
        private final String method;
        private final String template;
        private final String[] segments;
        private String summary = "";
        private Type body;
        private Type response;
        private Handler handler;

        private Route(String method, String template) {
            this.method = method;
            this.template = template;
            this.segments = split(template);
        }

        Route summary(String text) {
            this.summary = text;
            return this;
        }

        Route body(Type type) {
            this.body = type;
            return this;
        }

        Route returns(Type type) {
            this.response = type;
            return this;
        }

        /** Completes the declaration and registers the route. */
        void handle(Handler h) {
            this.handler = h;
            routes.add(this);
        }

        private Map<String, String> match(String requestMethod, String[] parts) {
            if (!method.equals(requestMethod) || parts.length != segments.length) {
                return null;
            }
            Map<String, String> params = new HashMap<>();
            for (int i = 0; i < parts.length; i++) {
                String seg = segments[i];
                if (isParam(seg)) {
                    if (parts[i].isEmpty()) {
                        return null;
                    }
                    params.put(seg.substring(1, seg.length() - 1), decode(parts[i]));
                } else if (!seg.equals(parts[i])) {
                    return null;
                }
            }
            return params;
        }
    }

    // ---- dispatch ------------------------------------------------------------

    @Override
    public void handle(HttpExchange ex) {
        try {
            String rel = ex.getRequestURI().getRawPath().substring(base.length());
            String method = ex.getRequestMethod();
            if ("GET".equals(method) && (rel.equals("/docs") || rel.equals("/docs/"))) {
                Http.send(ex, 200, "text/html; charset=utf-8", swaggerPage().getBytes(StandardCharsets.UTF_8));
            } else if ("GET".equals(method) && rel.startsWith("/docs/")) {
                serveSwaggerAsset(ex, rel.substring("/docs/".length()));
            } else if ("GET".equals(method) && rel.equals("/openapi.json")) {
                Http.send(ex, 200, "application/json", Http.JSON.writerWithDefaultPrettyPrinter()
                        .writeValueAsBytes(openApi()));
            } else {
                dispatch(ex, method, rel);
            }
        } catch (Exception e) {
            Http.error(ex, 500, String.valueOf(e.getMessage()));
        } finally {
            ex.close();
        }
    }

    private void dispatch(HttpExchange ex, String method, String rel) throws Exception {
        String[] parts = split(rel);
        for (Route route : routes) {
            Map<String, String> params = route.match(method, parts);
            if (params != null) {
                route.handler.handle(ex, params);
                return;
            }
        }
        Http.error(ex, 404, "no route: " + method + " " + ex.getRequestURI().getPath());
    }

    private static String[] split(String path) {
        return (path.startsWith("/") ? path.substring(1) : path).split("/", -1);
    }

    private static boolean isParam(String segment) {
        return segment.startsWith("{") && segment.endsWith("}");
    }

    /** Percent-decodes one path segment; a literal '+' stays a '+' (it is not a space in a path). */
    private static String decode(String segment) {
        return URLDecoder.decode(segment.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    // ---- OpenAPI ---------------------------------------------------------------

    private Map<String, Object> openApi() {
        Map<String, Object> schemas = new TreeMap<>();
        Map<String, Object> paths = new LinkedHashMap<>();
        for (Route route : routes) {
            Map<String, Object> op = obj("summary", route.summary, "tags", List.of(title));
            List<Object> params = new ArrayList<>();
            for (String seg : route.segments) {
                if (isParam(seg)) {
                    params.add(obj("name", seg.substring(1, seg.length() - 1), "in", "path",
                            "required", true, "schema", obj("type", "string")));
                }
            }
            if (!params.isEmpty()) {
                op.put("parameters", params);
            }
            if (route.body != null) {
                op.put("requestBody", obj("required", true, "content", jsonContent(schema(route.body, schemas))));
            }
            Map<String, Object> responses = new LinkedHashMap<>();
            responses.put("200", route.response == null ? obj("description", "OK")
                    : obj("description", "OK", "content", jsonContent(schema(route.response, schemas))));
            responses.put("default", obj("description", "Error",
                    "content", jsonContent(schema(Http.ApiError.class, schemas))));
            op.put("responses", responses);
            @SuppressWarnings("unchecked")
            Map<String, Object> item = (Map<String, Object>) paths.computeIfAbsent(route.template,
                    k -> new LinkedHashMap<String, Object>());
            item.put(route.method.toLowerCase(Locale.ROOT), op);
        }
        return obj("openapi", "3.0.3",
                "info", obj("title", title, "version", "v1", "description", description),
                "servers", List.of(obj("url", base)),
                "paths", paths,
                "components", obj("schemas", schemas));
    }

    private static Map<String, Object> jsonContent(Map<String, Object> schema) {
        return obj("application/json", obj("schema", schema));
    }

    /** A JSON schema for {@code type}; records become named components, mirroring how Jackson serializes them. */
    private static Map<String, Object> schema(Type type, Map<String, Object> components) {
        if (type instanceof ParameterizedType p) {
            if (p.getRawType() instanceof Class<?> raw && Collection.class.isAssignableFrom(raw)) {
                return obj("type", "array", "items", schema(p.getActualTypeArguments()[0], components));
            }
            return obj("type", "object");
        }
        if (!(type instanceof Class<?> c)) {
            return obj("type", "object");
        }
        if (c == String.class) {
            return obj("type", "string");
        } else if (c == int.class || c == Integer.class) {
            return obj("type", "integer", "format", "int32");
        } else if (c == long.class || c == Long.class) {
            return obj("type", "integer", "format", "int64");
        } else if (c == boolean.class || c == Boolean.class) {
            return obj("type", "boolean");
        } else if (c == byte[].class) {
            return obj("type", "string", "format", "byte");
        } else if (c.isRecord()) {
            String name = c.getSimpleName();
            if (!components.containsKey(name)) {
                components.put(name, obj()); // placeholder, so a self-referencing record terminates
                Map<String, Object> props = new LinkedHashMap<>();
                for (RecordComponent rc : c.getRecordComponents()) {
                    props.put(rc.getName(), schema(rc.getGenericType(), components));
                }
                components.put(name, obj("type", "object", "properties", props));
            }
            return obj("$ref", "#/components/schemas/" + name);
        }
        return obj("type", "object");
    }

    /** An insertion-ordered JSON object from alternating keys and values. */
    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    // ---- Swagger UI ------------------------------------------------------------

    private String swaggerPage() {
        return """
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1">
                  <title>%1$s · ReconMail API</title>
                  <link rel="stylesheet" href="%2$s/docs/swagger-ui.css">
                  <link rel="icon" type="image/png" href="%2$s/docs/favicon-32x32.png">
                </head>
                <body>
                  <div id="swagger-ui"></div>
                  <script src="%2$s/docs/swagger-ui-bundle.js"></script>
                  <script src="%2$s/docs/swagger-ui-standalone-preset.js"></script>
                  <script>
                    window.ui = SwaggerUIBundle({
                      url: "%2$s/openapi.json",
                      dom_id: "#swagger-ui",
                      deepLinking: true,
                      presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
                      layout: "StandaloneLayout"
                    });
                  </script>
                </body>
                </html>
                """.formatted(title, base);
    }

    /** Serves a Swagger UI file (JS/CSS/icons) straight out of the swagger-ui webjar on the classpath. */
    private static void serveSwaggerAsset(HttpExchange ex, String name) throws IOException {
        InputStream in = name.matches("[A-Za-z0-9_-][A-Za-z0-9._-]*")
                ? Router.class.getClassLoader().getResourceAsStream(SWAGGER_UI + name) : null;
        if (in == null) {
            Http.error(ex, 404, "no such docs asset: " + name);
            return;
        }
        try (in) {
            Http.send(ex, 200, contentType(name), in.readAllBytes());
        }
    }

    private static String contentType(String name) {
        if (name.endsWith(".js")) {
            return "text/javascript";
        } else if (name.endsWith(".css")) {
            return "text/css";
        } else if (name.endsWith(".png")) {
            return "image/png";
        } else if (name.endsWith(".html")) {
            return "text/html; charset=utf-8";
        }
        return "application/octet-stream";
    }

    /** The webjar's own version, so the pom is the single place it is pinned. */
    private static String swaggerUiVersion() {
        try (InputStream in = Router.class.getClassLoader()
                .getResourceAsStream("META-INF/maven/org.webjars/swagger-ui/pom.properties")) {
            Properties p = new Properties();
            p.load(in);
            return p.getProperty("version");
        } catch (Exception e) {
            throw new IllegalStateException("the swagger-ui webjar is missing from the classpath", e);
        }
    }
}
