# 02 — Authentication with SRP (login without sending a password)

*Proton logs you in without the server ever seeing your password. It uses **SRP-6a**
(Secure Remote Password), an augmented PAKE. This chapter reconstructs the exact
flow Proton uses, including the two details that make Proton's variant distinctive:
a **server-signed modulus** and **versioned password hashing**.*

## 1. Why SRP

A password sent to the server — even over TLS, even hashed — is a password the
server (or a breach of it) can capture. SRP avoids this: the server stores a
**verifier** `v` derived from the password, and the login is a zero-knowledge
proof that the client knows the password, producing a shared session key on both
sides. The server never receives anything it can invert to the password, and a
stolen verifier cannot be replayed as a password.

Parameters: a 2048-bit safe-prime modulus `N`, generator `g = 2`, hash-based
helper functions.

## 2. Registration (what the server ends up storing)

At signup the **client** computes everything:

1. Receive/choose the auth **version** and a random **salt**.
2. `x = H_pwd(version, password, salt, N)` — the versioned password hash (§4).
3. `v = g^x mod N` — the **verifier**.
4. Send `{ salt, verifier v, version }` to the server.

The server stores `(salt, v, version)` for the account. It never has `x` or the
password. (Compare chapter 01: this derivation is *independent* from the key
passphrase derivation, even in single-password mode.)

## 3. The login handshake

```
CLIENT                                                   SERVER
  │  POST /auth/info { username }                           │
  │ ──────────────────────────────────────────────────────▶│
  │                                      looks up (salt,v,version)
  │   { Modulus (PGP-signed), ServerEphemeral B,            │
  │     Salt, SRPSession, Version }                         │
  │ ◀──────────────────────────────────────────────────────│
  │                                                         │
  │ 1. VERIFY the PGP signature on Modulus with Proton's    │
  │    SRP key; only then extract N.   ◀── critical step    │
  │ 2. x = H_pwd(version, password, Salt, N)                │
  │ 3. pick random a;  A = g^a mod N                         │
  │ 4. u = H(A | B);  S = (B − k·g^x)^(a + u·x) mod N        │
  │    K = H(S);  M1 = H(A | B | K)                         │
  │                                                         │
  │  POST /auth { SRPSession, ClientEphemeral A,            │
  │               ClientProof M1 }                          │
  │ ──────────────────────────────────────────────────────▶│
  │                        server verifies M1 against v,    │
  │                        computes M2 = H(A | M1 | K)      │
  │   { ServerProof M2, AccessToken, RefreshToken, UID,     │
  │     Scope, 2FA? }                                       │
  │ ◀──────────────────────────────────────────────────────│
  │ 5. VERIFY M2. If it fails, the server is not genuine —  │
  │    abort.                                               │
  │ 6. If 2FA required: POST /auth/2fa { TOTP or FIDO2 }    │
```

Two mutual proofs: `M1` proves the client knows the password; `M2` proves the
server knows the verifier. Both sides also derive the same session key `K`.

### The signed modulus (don't skip it)
Proton serves `N` wrapped as an **ASCII-armored, PGP-signed message**, signed by a
Proton SRP key the client ships with. The client **must verify that signature
before using `N`**. Without this check, a malicious server could feed a weak or
trapdoored modulus and defeat SRP entirely. This is a Proton-specific hardening on
top of textbook SRP-6a.

## 4. Versioned password hashing `H_pwd`

Proton versions the password-hash function so the scheme can evolve without
breaking existing accounts. The modern versions (3 and 4):

1. `b = bcrypt(password, bcryptSaltFrom(salt))` — bcrypt (cost ~10) over the
   password with the per-user salt encoded into bcrypt's salt format.
2. `x = expandHash( b ‖ N )` — the bcrypt output concatenated with the modulus,
   run through an **expand-hash** (repeated SHA-512 producing a fixed 256-bit /
   long output) to get the SRP exponent input.

The exact byte-level construction lives in Proton's `go-srp` / `proton-python-client`
and should be copied from there for wire compatibility; the important invariants
for a reconstruction are: **bcrypt with a per-user salt**, **domain-separated by
the modulus**, and **versioned** so older accounts still authenticate.

## 5. Second factor and sessions

- **2FA:** TOTP (RFC 6238) or **FIDO2 / WebAuthn** security keys, as a step after
  the SRP exchange succeeds (`/auth/2fa`). The SRP session is only fully scoped
  once 2FA passes.
- **Session tokens:** on success the server issues
  - `UID` — session identifier (sent as `x-pm-uid`),
  - `AccessToken` — short-lived bearer token (`Authorization: Bearer …`),
  - `RefreshToken` — used at `/auth/refresh` to mint a new access token,
  - `Scope` — what the session may do (full access only after 2FA).
- Every subsequent API call carries `x-pm-uid` + the bearer access token.

## 6. Implications for our reconstruction

Our Java `auth-server` must provide:
- An SRP-6a engine (2048-bit `N`, `g=2`) with Proton-style proofs.
- A **signed-modulus** endpoint: serve `N` as a PGP-signed blob; the client
  verifies it (reuses the crypto core from chapter 01).
- Versioned `H_pwd` = bcrypt(+salt) → expandHash(‖N). We will implement version 4
  and keep the version field for forward-compat.
- `/auth/info`, `/auth`, `/auth/2fa`, `/auth/refresh` endpoints.
- Token issuance: `UID` + access/refresh (JWT or opaque), with scope gating on 2FA.

## Sources

- Proton — go-srp (reference SRP implementation): https://github.com/ProtonMail/go-srp
- Proton — python client (readable SRP + auth flow): https://github.com/ProtonMail/proton-python-client
- marinthiercelin/go-srp (Proton-related fork; Auth struct carries modulus + signature): https://pkg.go.dev/github.com/marinthiercelin/go-srp
- Proton patent — "System and method for secure password-based authentication": https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/8689003
- SRP-6a / RFC 5054: https://www.rfc-editor.org/rfc/rfc5054
- TOTP RFC 6238: https://www.rfc-editor.org/rfc/rfc6238
