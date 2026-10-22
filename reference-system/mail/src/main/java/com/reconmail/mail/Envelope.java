package com.reconmail.mail;

/**
 * Routing metadata only — no body (drafted by manzi). What an inbox listing
 * returns; the server can read all of it.
 */
public record Envelope(String id, String fromAddress, String toAddress, String subject,
                       long timestampEpochSeconds, int flags) {
}
