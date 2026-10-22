package com.reconmail.mail;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory message store (dossier chapter 05 data model). Holds opaque PGP
 * ciphertext blobs plus server-readable metadata.
 */
public final class MailStore {

    private final Map<String, StoredMessage> byId = new ConcurrentHashMap<>();

    public void put(StoredMessage message) {
        byId.put(message.id(), message);
    }

    public StoredMessage get(String id) {
        return byId.get(id);
    }

    /** The server can list an inbox from metadata alone — it never opens the blobs. */
    public List<Envelope> inboxOf(String toAddress) {
        List<Envelope> out = new ArrayList<>();
        for (StoredMessage m : byId.values()) {
            if (m.toAddress().equalsIgnoreCase(toAddress)) {
                out.add(new Envelope(m.id(), m.fromAddress(), m.toAddress(),
                        m.subject(), m.timestampEpochSeconds(), m.flags()));
            }
        }
        return out;
    }

    public int size() {
        return byId.size();
    }
}
