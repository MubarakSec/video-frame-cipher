"""
VFC core: ties every layer together (spec sections 28-29).

Operates on:
  * a grayscale frame (2D list of ints)      -> fingerprint / key material
  * a WavAudio object (16-bit PCM)            -> steganographic carrier
  * the secret file bytes                     -> the thing being hidden

The original filename, size and compression flag are stored INSIDE the
encrypted plaintext, so nothing about the hidden file leaks in the clear.
"""

import os
import zlib

from .cipher import cbc_encrypt, cbc_decrypt, ROUNDS
from .fingerprint import fingerprint_from_gray
from .keys import derive_k_embed, derive_enc_auth, expand_round_keys, compute_magic, constant_time_eq
from .prng import shuffled_positions
from . import payload as payload_mod
from .stego import WavAudio, embed, extract

# Guard rail against a crafted header claiming an absurd ciphertext length.
MAX_CIPHERTEXT = 64 * 1024 * 1024  # 64 MiB


# ---------------------------------------------------------------------------
# inner plaintext (metadata + file bytes), all encrypted
# ---------------------------------------------------------------------------

def _pack_plaintext(filename: str, data: bytes, compress: bool):
    flags = 0
    body = data
    if compress:
        packed = zlib.compress(data, 9)
        if len(packed) < len(data):   # only keep compression if it helped
            body = packed
            flags |= 1
    name = filename.encode("utf-8")
    return (
        len(name).to_bytes(2, "big")
        + name
        + len(data).to_bytes(8, "big")   # ORIGINAL (uncompressed) size
        + bytes([flags])
        + body
    )


def _unpack_plaintext(plain: bytes):
    name_len = int.from_bytes(plain[0:2], "big")
    off = 2
    name = os.path.basename(plain[off:off + name_len].decode("utf-8"))
    if not name or "\x00" in name:
        raise ValueError("invalid filename in payload")
    off += name_len
    orig_size = int.from_bytes(plain[off:off + 8], "big")
    off += 8
    flags = plain[off]
    off += 1
    body = plain[off:]
    data = zlib.decompress(body) if (flags & 1) else body
    if len(data) != orig_size:
        raise ValueError("size mismatch after decompression")
    return name, data


# ---------------------------------------------------------------------------
# encrypt
# ---------------------------------------------------------------------------

def encrypt(frame_gray, audio: WavAudio, secret_bytes: bytes, filename: str,
            password: bytes, frame_no: int, compress: bool = True, force: bool = False,
            progress_cb=None):
    """Hide `secret_bytes` inside `audio`, keyed by password + frame. In place."""
    if progress_cb:
        progress_cb(0.05, "Deriving encryption keys (PBKDF2)...")
    fingerprint = fingerprint_from_gray(frame_gray)
    salt = os.urandom(16)
    iv = os.urandom(16)

    k_embed = derive_k_embed(password, fingerprint, frame_no)
    k_enc, k_auth = derive_enc_auth(password, fingerprint, frame_no, salt)
    round_keys = expand_round_keys(k_enc, ROUNDS)

    if progress_cb:
        progress_cb(0.10, "Packing & compressing secret plaintext...")
    plaintext = _pack_plaintext(filename, secret_bytes, compress)

    def _cipher_cb(frac):
        if progress_cb:
            progress_cb(0.15 + 0.25 * frac, f"SPN CBC Block Encryption ({int(frac * 100)}%)...")

    ciphertext = cbc_encrypt(plaintext, round_keys, iv, progress_cb=_cipher_cb)

    if len(ciphertext) > MAX_CIPHERTEXT and not force:
        raise ValueError(
            f"secret too large: ciphertext is {len(ciphertext)} bytes, "
            f"decryption ceiling is {MAX_CIPHERTEXT} (64 MiB)"
        )

    if progress_cb:
        progress_cb(0.42, "Constructing HMAC authenticated payload...")
    full_payload = payload_mod.build(k_embed, k_auth, salt, iv, frame_no, ciphertext)

    eligible = audio.eligible_indices()

    def _prng_cb(frac):
        if progress_cb:
            progress_cb(0.45 + 0.25 * frac, f"Generating CSPRNG sample positions ({int(frac * 100)}%)...")

    positions = shuffled_positions(k_embed, eligible, progress_cb=_prng_cb)

    need_bits = len(full_payload) * 8
    is_truncated = need_bits > len(positions)
    if is_truncated and not force:
        raise ValueError(
            f"audio too small: need {need_bits} eligible samples, have {len(positions)}"
        )

    def _embed_cb(frac):
        if progress_cb:
            progress_cb(0.70 + 0.28 * frac, f"Embedding payload into audio LSBs ({int(frac * 100)}%)...")

    embed(audio, full_payload, positions, force=force, progress_cb=_embed_cb)

    if progress_cb:
        progress_cb(1.0, "Core encryption & embedding finished.")

    return {
        "fingerprint": fingerprint.hex(),
        "payload_bytes": len(full_payload),
        "ciphertext_bytes": len(ciphertext),
        "eligible_samples": len(eligible),
        "used_samples": min(need_bits, len(positions)),
        "needed_samples": need_bits,
        "capacity_pct": 100.0 * need_bits / (len(positions) or 1),
        "truncated": is_truncated,
    }


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------

def decrypt(frame_gray, audio: WavAudio, password: bytes, frame_no: int, progress_cb=None):
    """Recover the hidden file. Raises ValueError on any failure."""
    if progress_cb:
        progress_cb(0.05, "Deriving K_embed and fingerprint...")
    fingerprint = fingerprint_from_gray(frame_gray)
    k_embed = derive_k_embed(password, fingerprint, frame_no)

    eligible = audio.eligible_indices()

    def _prng_cb(frac):
        if progress_cb:
            progress_cb(0.10 + 0.30 * frac, f"Generating sample positions ({int(frac * 100)}%)...")

    positions = shuffled_positions(k_embed, eligible, progress_cb=_prng_cb)

    # 1) read the fixed-length header first
    if progress_cb:
        progress_cb(0.42, "Extracting payload header & magic check...")
    header_bits = payload_mod.HEADER_LEN * 8
    if header_bits > len(positions):
        raise ValueError("authentication failed")
    header = extract(audio, positions, header_bits)
    hdr = payload_mod.read_header(header)

    # 2) fast fail on key-derived magic (constant-time)
    if not constant_time_eq(hdr["magic"], compute_magic(k_embed)):
        raise ValueError("authentication failed")

    # 3) sanity-check the claimed length BEFORE reading more (anti-DoS)
    ct_len = hdr["ct_len"]
    if ct_len < 0 or ct_len > MAX_CIPHERTEXT or (ct_len % 16) != 0:
        raise ValueError("authentication failed")
    total_bits = payload_mod.total_len(ct_len) * 8
    if total_bits > len(positions):
        raise ValueError("authentication failed")

    # 4) read the whole payload and verify the tag
    def _extract_cb(frac):
        if progress_cb:
            progress_cb(0.45 + 0.32 * frac, f"Extracting payload LSBs ({int(frac * 100)}%)...")

    full = extract(audio, positions, total_bits, progress_cb=_extract_cb)

    if progress_cb:
        progress_cb(0.78, "Verifying HMAC authentication tag...")
    k_enc, k_auth = derive_enc_auth(password, fingerprint, frame_no, hdr["salt"])
    ciphertext = payload_mod.verify_and_split(full, k_auth)   # raises on bad tag

    # 5) decrypt only after authentication succeeds
    def _cipher_cb(frac):
        if progress_cb:
            progress_cb(0.80 + 0.18 * frac, f"Decrypting SPN blocks ({int(frac * 100)}%)...")

    round_keys = expand_round_keys(k_enc, ROUNDS)
    plaintext = cbc_decrypt(ciphertext, round_keys, hdr["iv"], progress_cb=_cipher_cb)

    if progress_cb:
        progress_cb(0.99, "Unpacking original plaintext file...")
    filename, data = _unpack_plaintext(plaintext)

    if progress_cb:
        progress_cb(1.0, "Decryption complete.")
    return filename, data
