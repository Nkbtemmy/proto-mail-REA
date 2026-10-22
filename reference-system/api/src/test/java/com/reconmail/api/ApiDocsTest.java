package com.reconmail.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.reconmail.persistence.Db;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Every service serves its own Swagger UI + OpenAPI document under {@code /api/v1/<service>}. */
class ApiDocsTest {

    /** The documented routes per service — the public contract. */
    private static final Map<String, Set<String>> ROUTES = Map.of(
            TestClient.AUTH, Set.of("/register", "/info", "/login", "/modulus-key"),
            TestClient.KEYS, Set.of("/keys", "/keys/{email}", "/keys/{email}/proof"),
            TestClient.MAIL, Set.of("/messages", "/messages/external", "/messages/{id}", "/messages/inbox/{email}"));

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void eachServiceServesItsDocsThroughTheGateway(@TempDir Path dir) throws Exception {
        try (Db db = Db.file(dir)) {
            Cluster cluster = new Cluster(db);
            try {
                for (String base : ROUTES.keySet()) {
                    assertDocs(cluster.gatewayBase(), base);
                }
                assertEquals(404, get(cluster.gatewayBase() + "/auth/modulus-key").statusCode(),
                        "the old unversioned paths are gone");
            } finally {
                cluster.stop();
            }
        }
    }

    @Test
    void theAllInOneServerServesTheSameDocs() throws Exception {
        HttpApiServer server = new HttpApiServer(0);
        server.start();
        try {
            String origin = "http://localhost:" + server.port();
            for (String base : ROUTES.keySet()) {
                assertDocs(origin, base);
            }
            assertEquals(404, get(origin + "/api/v1/nope").statusCode());
        } finally {
            server.stop();
        }
    }

    private void assertDocs(String origin, String base) throws Exception {
        HttpResponse<String> page = get(origin + base + "/docs");
        assertEquals(200, page.statusCode(), base + "/docs");
        assertTrue(page.headers().firstValue("Content-Type").orElse("").startsWith("text/html"));
        assertTrue(page.body().contains(base + "/openapi.json"), "the page loads its own service's spec");

        HttpResponse<String> bundle = get(origin + base + "/docs/swagger-ui-bundle.js");
        assertEquals(200, bundle.statusCode(), "Swagger UI assets are served from the webjar");
        assertEquals(404, get(origin + base + "/docs/..%2Fpom.properties").statusCode(), "no path escape");

        HttpResponse<String> specResponse = get(origin + base + "/openapi.json");
        assertEquals(200, specResponse.statusCode(), base + "/openapi.json");
        JsonNode spec = json.readTree(specResponse.body());
        assertEquals("3.0.3", spec.path("openapi").asText());
        assertEquals(base, spec.path("servers").path(0).path("url").asText());

        Set<String> paths = new TreeSet<>();
        spec.path("paths").fieldNames().forEachRemaining(paths::add);
        assertEquals(new TreeSet<>(ROUTES.get(base)), paths, base + " documents exactly its routes");

        JsonNode schemas = spec.path("components").path("schemas");
        for (String ref : spec.findValuesAsText("$ref")) {
            String name = ref.substring("#/components/schemas/".length());
            assertTrue(schemas.path(name).has("properties"), "dangling or empty $ref " + ref);
        }
    }

    private HttpResponse<String> get(String url) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }
}
