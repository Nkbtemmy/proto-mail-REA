package com.reconmail.persistence;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/** Durable store for SRP credentials (the auth service's state). */
public final class UserRepo {

    public record UserRow(String username, String saltB64, String verifierHex, int version) {}

    private final Db db;

    public UserRepo(Db db) {
        this.db = db;
    }

    public void upsert(String username, String saltB64, String verifierHex, int version) {
        synchronized (db) {
            try (PreparedStatement ps = db.connection().prepareStatement(
                    "MERGE INTO users (username, salt_b64, verifier_hex, version) KEY(username) VALUES (?,?,?,?)")) {
                ps.setString(1, username);
                ps.setString(2, saltB64);
                ps.setString(3, verifierHex);
                ps.setInt(4, version);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public List<UserRow> findAll() {
        synchronized (db) {
            List<UserRow> out = new ArrayList<>();
            try (PreparedStatement ps = db.connection().prepareStatement(
                    "SELECT username, salt_b64, verifier_hex, version FROM users");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(new UserRow(rs.getString(1), rs.getString(2), rs.getString(3), rs.getInt(4)));
                }
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
            return out;
        }
    }
}
