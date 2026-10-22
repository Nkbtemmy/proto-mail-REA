package com.reconmail.persistence;

import com.reconmail.mail.StoredMessage;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/** Durable store for stored messages (the mail service's state). */
public final class MessageRepo {

    private final Db db;

    public MessageRepo(Db db) {
        this.db = db;
    }

    public void insert(StoredMessage m) {
        synchronized (db) {
            try (PreparedStatement ps = db.connection().prepareStatement(
                    "MERGE INTO messages (id, from_addr, to_addr, subject, ts, flags, ciphertext)"
                            + " KEY(id) VALUES (?,?,?,?,?,?,?)")) {
                ps.setString(1, m.id());
                ps.setString(2, m.fromAddress());
                ps.setString(3, m.toAddress());
                ps.setString(4, m.subject());
                ps.setLong(5, m.timestampEpochSeconds());
                ps.setInt(6, m.flags());
                ps.setString(7, m.ciphertextArmored());
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public List<StoredMessage> findAll() {
        synchronized (db) {
            List<StoredMessage> out = new ArrayList<>();
            try (PreparedStatement ps = db.connection().prepareStatement(
                    "SELECT id, from_addr, to_addr, subject, ts, flags, ciphertext FROM messages");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(new StoredMessage(rs.getString(1), rs.getString(2), rs.getString(3),
                            rs.getString(4), rs.getLong(5), rs.getInt(6), rs.getString(7)));
                }
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
            return out;
        }
    }
}
