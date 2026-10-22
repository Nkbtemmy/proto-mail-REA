package com.reconmail.persistence;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * A tiny embedded-SQL database (H2) behind the repositories. Durable: data written
 * here survives a process restart (proven in PersistenceRestartTest). Swapping to
 * Postgres is a JDBC-URL + driver change — the repository SQL is standard.
 *
 * <p>One shared connection; repositories synchronize on this object per operation.</p>
 */
public final class Db implements AutoCloseable {

    private final Connection connection;

    public Db(String jdbcUrl) {
        try {
            this.connection = DriverManager.getConnection(jdbcUrl, "sa", "");
            initSchema();
        } catch (SQLException e) {
            throw new RuntimeException("database init failed: " + jdbcUrl, e);
        }
    }

    /** A file-backed H2 database under {@code dir} (durable across restarts). */
    public static Db file(Path dir) {
        return new Db("jdbc:h2:file:" + dir.resolve("reconmail").toAbsolutePath());
    }

    Connection connection() {
        return connection;
    }

    private void initSchema() throws SQLException {
        try (Statement s = connection.createStatement()) {
            s.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                      username VARCHAR PRIMARY KEY, salt_b64 VARCHAR, verifier_hex VARCHAR, version INT)""");
            s.execute("""
                    CREATE TABLE IF NOT EXISTS keys (
                      email VARCHAR PRIMARY KEY, username VARCHAR, key_salt VARCHAR,
                      enc_user_priv VARCHAR, user_pub VARCHAR, enc_addr_priv VARCHAR,
                      enc_addr_token VARCHAR, addr_pub VARCHAR, skl_json VARCHAR, skl_sig VARCHAR)""");
            s.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                      id VARCHAR PRIMARY KEY, from_addr VARCHAR, to_addr VARCHAR, subject VARCHAR,
                      ts BIGINT, flags INT, ciphertext VARCHAR)""");
        }
    }

    @Override
    public void close() {
        try {
            connection.close();
        } catch (SQLException ignored) {
            // closing a shared connection on shutdown
        }
    }
}
