package com.reconmail.keyserver.api;

import java.util.List;

/**
 * Response returning an address's public keys from the directory (wire DTO; see
 * dossier chapter 03 §1). Drafted by manzi (Qwen 14B).
 *
 * @param email        the email address
 * @param keys         the published public key entries
 * @param sklSignature the signature over the address's signed key list
 * @param epochId      the Key Transparency epoch these keys were committed in
 */
public record KeyDirectoryResponse(String email, List<PublicKeyEntry> keys,
                                   String sklSignature, long epochId) {}
