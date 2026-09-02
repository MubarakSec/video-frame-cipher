"""
Key derivation for VFC v0.2.

Design decisions locked in review:

1. Salt circular dependency FIX.
   Decryption must locate the hidden payload (which contains the salt) before
   it can read the salt. So the embedding key K_embed is derived WITHOUT the
   salt. The salt still strengthens the encryption/authentication keys.

       K_embed = KDF(password, "VFC-EMBED"   || fingerprint || frame_no)
       K_enc   = KDF(password, "VFC-ENCRYPT" || fingerprint || frame_no || salt)
       K_auth  = KDF(password, "VFC-AUTH"    || fingerprint || frame_no || salt)

   Decrypt order: fingerprint -> K_embed -> positions -> payload -> salt
                  -> K_enc / K_auth -> verify -> decrypt.

2. Threat-model honesty.
   The frame fingerprint is NOT a secret (the attacker may hold the video and
   frame number). It provides key diversification and binds the keys to the
   carrier video. The PASSWORD is the only real secret; the KDF work factor is
   therefore the real security parameter.

3. Key-derived magic.
   The 4-byte payload marker is derived from K_embed, so an attacker cannot
   read plaintext bytes to test a password guess for free. Computing it costs
   a full PBKDF2 (same as any other check), so it is not a cheap oracle.
"""

import hashlib
import hmac

# PBKDF2 work factor. Higher = slower brute force. Documented, not left to
# "an implementation parameter". Raise for real deployments.
PBKDF2_ITERATIONS = 200_000


def _kdf(password: bytes, info: bytes, salt: bytes = b"") -> bytes:
    """PBKDF2-HMAC-SHA256 -> 32 bytes. `info` is folded into the salt input."""
    return hashlib.pbkdf2_hmac("sha256", password, info + salt, PBKDF2_ITERATIONS, dklen=32)


def derive_k_embed(password: bytes, fingerprint: bytes, frame_no: int) -> bytes:
    """Embedding key. NO salt -> recoverable before the payload is located."""
    info = b"VFC-EMBED" + fingerprint + frame_no.to_bytes(4, "big")
    return _kdf(password, info)


def derive_enc_auth(password: bytes, fingerprint: bytes, frame_no: int, salt: bytes):
    """Encryption + authentication keys. Salt-dependent."""
    fn = frame_no.to_bytes(4, "big")
    k_enc = _kdf(password, b"VFC-ENCRYPT" + fingerprint + fn, salt)
    k_auth = _kdf(password, b"VFC-AUTH" + fingerprint + fn, salt)
    return k_enc, k_auth


def compute_magic(k_embed: bytes) -> bytes:
    """4-byte key-derived payload marker."""
    return hashlib.sha256(k_embed + b"VFC-MAGIC").digest()[:4]


def expand_round_keys(k_enc: bytes, rounds: int):
    """Distinct round keys from K_enc.

    Using a per-round domain label ("VFC-RK" || i) gives independent-looking
    round keys and avoids the slide-attack exposure of reusing one key each
    round.
    """
    return [
        hashlib.sha256(k_enc + b"VFC-RK" + i.to_bytes(2, "big")).digest()[:16]
        for i in range(rounds + 1)
    ]


def hmac_tag(k_auth: bytes, data: bytes) -> bytes:
    return hmac.new(k_auth, data, hashlib.sha256).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Timing-safe comparison (do not use ==)."""
    return hmac.compare_digest(a, b)
