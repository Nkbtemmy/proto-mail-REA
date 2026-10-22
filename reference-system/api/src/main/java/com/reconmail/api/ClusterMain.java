package com.reconmail.api;

import com.reconmail.persistence.Db;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Boots the split, persistent stack (gateway + auth/keys/mail services over a
 * durable H2 database).
 * Run: {@code mvn -f reference-system/api/pom.xml -q -Dexec.mainClass=com.reconmail.api.ClusterMain exec:java -Dexec.args=reconmail-data}
 */
public final class ClusterMain {

    public static void main(String[] args) throws Exception {
        Path dir = Path.of(args.length > 0 ? args[0] : "reconmail-data");
        Files.createDirectories(dir);
        Cluster cluster = new Cluster(Db.file(dir));
        System.out.println("ReconMail cluster up — gateway at " + cluster.gatewayBase());
        System.out.println("  backends: auth=" + cluster.auth.port()
                + " keys=" + cluster.keys.port() + " mail=" + cluster.mail.port());
        System.out.println("  data dir: " + dir.toAbsolutePath());
        System.out.println("  Swagger UI:");
        for (String base : new String[]{ApiPaths.AUTH, ApiPaths.KEYS, ApiPaths.MAIL}) {
            System.out.println("    " + cluster.gatewayBase() + base + "/docs");
        }
        Runtime.getRuntime().addShutdownHook(new Thread(cluster::stop));
    }
}
