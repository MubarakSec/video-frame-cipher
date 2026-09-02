"""
Payload structure, authentication, and parsing (spec sections 26-27).

Layout (all fields at K_embed-derived positions; no separate bootstrap region
is needed because K_embed does not depend on the salt):

    offset  field          size   secret?  notes
    ------  -------------  -----   -------  -------------------------------
    0       magic            4     no       SHA256(K_embed || "VFC-MAGIC")[:4]
    4       version          1     no
    5       flags            1     no       reserved
    6       salt            16     no       KDF salt (public by design)
    22      iv              16     no       CBC IV (public by design)
    38      frame_no         4     no
    42      ct_len           8     no       ciphertext length
    50      ciphertext     ct_len  ENC      file metadata + data live in here
    ...     tag             32     no       HMAC-SHA256 over bytes [0 : 50+ct_len]

The original file's TYPE and SIZE are placed INSIDE the ciphertext (see core.py)
so they are not exposed in the clear.

HMAC coverage: the tag authenticates the entire header (magic, version, flags,
salt, iv, frame_no, ct_len) AND the ciphertext. Flipping any IV/salt bit
therefore fails authentication.
"""

from . import keys

VERSION = 2
HEADER_LEN = 50          # bytes before ciphertext
TAG_LEN = 32
MAGIC_LEN = 4


def build(k_embed: bytes, k_auth: bytes, salt: bytes, iv: bytes,
          frame_no: int, ciphertext: bytes) -> bytes:
    magic = keys.compute_magic(k_embed)
    header = (
        magic
        + bytes([VERSION, 0])
        + salt
        + iv
        + frame_no.to_bytes(4, "big")
        + len(ciphertext).to_bytes(8, "big")
    )
    assert len(header) == HEADER_LEN
    body = header + ciphertext
    tag = keys.hmac_tag(k_auth, body)
    return body + tag


def read_header(header_bytes: bytes):
    """Parse the fixed 50-byte header prefix. Returns a dict of fields."""
    if len(header_bytes) < HEADER_LEN:
        raise ValueError("truncated header")
    return {
        "magic": header_bytes[0:4],
        "version": header_bytes[4],
        "flags": header_bytes[5],
        "salt": header_bytes[6:22],
        "iv": header_bytes[22:38],
        "frame_no": int.from_bytes(header_bytes[38:42], "big"),
        "ct_len": int.from_bytes(header_bytes[42:50], "big"),
    }


def total_len(ct_len: int) -> int:
    return HEADER_LEN + ct_len + TAG_LEN


def verify_and_split(full: bytes, k_auth: bytes):
    """Check the tag and return the ciphertext, or raise on failure."""
    hdr = read_header(full)
    ct_len = hdr["ct_len"]
    end = HEADER_LEN + ct_len
    body, tag = full[:end], full[end:end + TAG_LEN]
    expected = keys.hmac_tag(k_auth, body)
    if not keys.constant_time_eq(tag, expected):
        raise ValueError("authentication failed: wrong password, wrong frame, "
                         "or corrupted payload")
    return full[HEADER_LEN:end]
