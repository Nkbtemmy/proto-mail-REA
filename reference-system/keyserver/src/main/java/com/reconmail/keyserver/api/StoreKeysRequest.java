package com.reconmail.keyserver.api;

/**
 * Request to store a user's encrypted key material in the vault (wire DTO; see
 * dossier chapter 03 §1). Drafted by manzi (Qwen 14B).
 *
 * @param username          the user's username
 * @param email             the user's email address
 * @param keySalt           base64-encoded key salt
 * @param encUserPrivateKey armored encrypted user private key
 * @param userPublicKey     armored user public key
 * @param encAddrPrivateKey armored encrypted address private key
 * @param encAddrToken      armored address token (encrypted to the user key)
 * @param addrPublicKey     armored address public key
 */
public record StoreKeysRequest(String username, String email, String keySalt,
                               String encUserPrivateKey, String userPublicKey,
                               String encAddrPrivateKey, String encAddrToken,
                               String addrPublicKey) {}
