# Crypto, auth, authorization
- Passwords: argon2id, bcrypt or scrypt with per-user salt. Not MD5/SHA-1/plain SHA-256. Migrating stored hashes is a design decision (rehash on next login): ask.
- Tokens/IDs/keys: `secrets` (Python), `crypto.randomBytes` (Node), `crypto/rand` (Go). Never `random`/`Math.random` for security.
- Compare secrets in constant time (`hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.ConstantTimeCompare`).
- TLS: never `verify=False` / `InsecureSkipVerify` / disabled cert checks outside a local test.
- Encryption: AES-GCM or ChaCha20-Poly1305 via a vetted library; no ECB, no home-made schemes, no hardcoded keys.
- JWT: pin the algorithm, verify signature, `exp`, `aud`, `iss`; reject `alg: none`.
- Authorization: check object ownership/permission server-side on every request (IDOR); deny by default; do not rely on hidden UI.
- Sessions: HttpOnly, Secure, SameSite cookies; rotate on login; rate-limit login and reset endpoints.
Changing auth behaviour is a stop-and-ask item.
