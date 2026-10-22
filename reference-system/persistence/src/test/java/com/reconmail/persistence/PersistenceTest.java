package com.reconmail.persistence;

import com.reconmail.keyserver.api.StoreKeysRequest;
import com.reconmail.mail.StoredMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PersistenceTest {

    @Test
    void dataSurvivesReopeningTheDatabase(@TempDir Path dir) {
        // Write with one Db instance...
        try (Db db = Db.file(dir)) {
            new UserRepo(db).upsert("alice", "c2FsdA==", "abc123", 4);
            new KeyRepo(db).upsert(new StoreKeysRequest("alice", "alice@recon.test", "c2FsdA==",
                    "encUser", "userPub", "encAddr", "encTok", "addrPub"), "[skl]", "sig");
            new MessageRepo(db).insert(new StoredMessage("m1", "a@x", "b@x", "Subj", 123L, 0, "CIPHERTEXT"));
        }

        // ...reopen a fresh Db over the same files and read it back.
        try (Db db = Db.file(dir)) {
            List<UserRepo.UserRow> users = new UserRepo(db).findAll();
            assertEquals(1, users.size());
            assertEquals("alice", users.get(0).username());
            assertEquals("abc123", users.get(0).verifierHex());

            List<KeyRepo.KeyRow> keys = new KeyRepo(db).findAll();
            assertEquals(1, keys.size());
            assertEquals("alice@recon.test", keys.get(0).keys().email());
            assertEquals("[skl]", keys.get(0).sklJson());

            List<StoredMessage> messages = new MessageRepo(db).findAll();
            assertEquals(1, messages.size());
            assertEquals("CIPHERTEXT", messages.get(0).ciphertextArmored());
            assertTrue(messages.get(0).subject().equals("Subj"));
        }
    }
}
