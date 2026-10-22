package com.reconmail.persistence;

import com.reconmail.keyserver.api.StoreKeysRequest;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/** Durable store for encrypted key material + signed key lists (the key service's state). */
public final class KeyRepo {

    public record KeyRow(StoreKeysRequest keys, String sklJson, String sklSig) {}

    private final Db db;

    public KeyRepo(Db db) {
        this.db = db;
    }

    public void upsert(StoreKeysRequest k, String sklJson, String sklSig) {
        synchronized (db) {
            try (PreparedStatement ps = db.connection().prepareStatement(
                    "MERGE INTO keys (email, username, key_salt, enc_user_priv, user_pub, enc_addr_priv,"
                            + " enc_addr_token, addr_pub, skl_json, skl_sig) KEY(email)"
                            + " VALUES (?,?,?,?,?,?,?,?,?,?)")) {
                ps.setString(1, k.email());
                ps.setString(2, k.username());
                ps.setString(3, k.keySalt());
                ps.setString(4, k.encUserPrivateKey());
                ps.setString(5, k.userPublicKey());
                ps.setString(6, k.encAddrPrivateKey());
                ps.setString(7, k.encAddrToken());
                ps.setString(8, k.addrPublicKey());
                ps.setString(9, sklJson);
                ps.setString(10, sklSig);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public List<KeyRow> findAll() {
        synchronized (db) {
            List<KeyRow> out = new ArrayList<>();
            try (PreparedStatement ps = db.connection().prepareStatement(
                    "SELECT email, username, key_salt, enc_user_priv, user_pub, enc_addr_priv,"
                            + " enc_addr_token, addr_pub, skl_json, skl_sig FROM keys");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    StoreKeysRequest keys = new StoreKeysRequest(
                            rs.getString(2), rs.getString(1), rs.getString(3), rs.getString(4),
                            rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8));
                    out.add(new KeyRow(keys, rs.getString(9), rs.getString(10)));
                }
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
            return out;
        }
    }
}
