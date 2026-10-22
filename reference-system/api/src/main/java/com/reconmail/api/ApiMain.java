package com.reconmail.api;

/**
 * Boots the ReconMail HTTP API.
 * Run: {@code mvn -f reference-system/api/pom.xml -q -Dexec.mainClass=com.reconmail.api.ApiMain exec:java}
 */
public final class ApiMain {

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpApiServer server = new HttpApiServer(port);
        server.start();
        String origin = "http://localhost:" + server.port();
        System.out.println("ReconMail API listening on " + origin);
        System.out.println("Swagger UI (routes + try-it-out):");
        for (String base : new String[]{ApiPaths.AUTH, ApiPaths.KEYS, ApiPaths.MAIL}) {
            System.out.println("  " + origin + base + "/docs");
        }
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
    }
}
