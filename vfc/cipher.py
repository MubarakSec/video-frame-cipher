"""
VFC custom block cipher (v0.2).

A small SPN (Substitution-Permutation Network) that operates on 128-bit
(16-byte) blocks. It exists to *demonstrate* the components of a modern
block cipher for an academic assignment, not to compete with AES.

The one non-negotiable property is REVERSIBILITY:  decrypt(encrypt(x)) == x.
Every layer below is bijective and its inverse is explicit.

Round (encryption):
    SubBytes  ->  ShiftRows  ->  MixColumns  ->  AddRoundKey

The MixColumns layer is the fix for the original design's fatal flaw:
without it, one input byte only ever affects one output byte. MixColumns
(a linear layer over GF(2^8)) makes every output byte of a column depend
on all four input bytes, and ShiftRows spreads that across columns, so
after two rounds every output byte depends on every input byte.
"""

import hashlib

# ---------------------------------------------------------------------------
# GF(2^8) arithmetic  (Rijndael field, irreducible polynomial 0x11B)
# ---------------------------------------------------------------------------

def gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11B)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B            # reduction step (the 0x11B poly minus x^8)
        b >>= 1
    return p


# The linear mixing matrix (circulant [2,3,1,1]) and its inverse.
# This matrix is MDS, so its determinant over GF(2^8) is non-zero and the
# inverse below satisfies  INV_MDS x MDS = Identity  (verified in tests.py).
MDS = (
    (2, 3, 1, 1),
    (1, 2, 3, 1),
    (1, 1, 2, 3),
    (3, 1, 1, 2),
)
INV_MDS = (
    (14, 11, 13, 9),
    (9, 14, 11, 13),
    (13, 9, 14, 11),
    (11, 13, 9, 14),
)


def mat_mul_gf(A, B):
    """4x4 x 4x4 matrix multiply over GF(2^8). Used only to *prove* invertibility."""
    out = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            acc = 0
            for k in range(4):
                acc ^= gmul(A[i][k], B[k][j])
            out[i][j] = acc
    return out


def is_identity(M) -> bool:
    for i in range(4):
        for j in range(4):
            if M[i][j] != (1 if i == j else 0):
                return False
    return True


def mds_is_invertible() -> bool:
    """Return True iff INV_MDS is a genuine inverse of MDS over GF(2^8)."""
    return is_identity(mat_mul_gf(INV_MDS, MDS))


# ---------------------------------------------------------------------------
# S-Box  (fixed bijective substitution, built deterministically from a seed)
# ---------------------------------------------------------------------------

def _build_sbox(seed: bytes):
    """Fisher-Yates shuffle of 0..255 driven by SHA-256(seed || counter).

    The S-Box is a fixed public parameter (not a secret). Being a permutation
    of 0..255 guarantees it is bijective, so an inverse exists.
    """
    perm = list(range(256))
    counter = 0
    pool = b""
    pos = 0

    def next_byte():
        nonlocal counter, pool, pos
        if pos >= len(pool):
            pool = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
            counter += 1
            pos = 0
        b = pool[pos]
        pos += 1
        return b

    for i in range(255, 0, -1):
        # unbiased index in [0, i] via rejection sampling
        limit = i + 1
        bound = (256 // limit) * limit
        while True:
            r = next_byte()
            if r < bound:
                break
        j = r % limit
        perm[i], perm[j] = perm[j], perm[i]

    inv = [0] * 256
    for idx, val in enumerate(perm):
        inv[val] = idx
    return perm, inv


SBOX, INV_SBOX = _build_sbox(b"VFC-SBOX-v0.2")

__all__ = [
    "gmul", "MDS", "INV_MDS", "mat_mul_gf", "is_identity", "mds_is_invertible",
    "SBOX", "INV_SBOX",
    "encrypt_block", "decrypt_block",
    "pkcs7_pad", "pkcs7_unpad",
    "cbc_encrypt", "cbc_decrypt",
    "ROUNDS",
]


# ---------------------------------------------------------------------------
# State helpers  (16 bytes <-> 4x4 column-major grid, like AES)
# ---------------------------------------------------------------------------

def _to_state(block: bytes):
    return [[block[c * 4 + r] for c in range(4)] for r in range(4)]


def _from_state(state) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Round layers
# ---------------------------------------------------------------------------

def _sub_bytes(state, box):
    return [[box[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state):
    # row r rotated left by r
    return [state[r][r:] + state[r][:r] for r in range(4)]


def _inv_shift_rows(state):
    # row r rotated right by r
    return [(state[r][-r:] + state[r][:-r]) if r else state[r][:] for r in range(4)]


def _mix_columns(state, matrix):
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[0][c], state[1][c], state[2][c], state[3][c]]
        for r in range(4):
            out[r][c] = (
                gmul(matrix[r][0], col[0]) ^
                gmul(matrix[r][1], col[1]) ^
                gmul(matrix[r][2], col[2]) ^
                gmul(matrix[r][3], col[3])
            )
    return out


def _add_round_key(state, rk: bytes):
    rks = _to_state(rk)
    return [[state[r][c] ^ rks[r][c] for c in range(4)] for r in range(4)]


ROUNDS = 6  # deliberately fewer than AES: enough for full diffusion + margin,
            # while making no claim to AES's security level.


def encrypt_block(block: bytes, round_keys) -> bytes:
    assert len(block) == 16
    state = _add_round_key(_to_state(block), round_keys[0])   # initial whitening
    for r in range(1, ROUNDS + 1):
        state = _sub_bytes(state, SBOX)
        state = _shift_rows(state)
        state = _mix_columns(state, MDS)
        state = _add_round_key(state, round_keys[r])
    return _from_state(state)


def decrypt_block(block: bytes, round_keys) -> bytes:
    assert len(block) == 16
    state = _to_state(block)
    for r in range(ROUNDS, 0, -1):
        state = _add_round_key(state, round_keys[r])
        state = _mix_columns(state, INV_MDS)
        state = _inv_shift_rows(state)
        state = _sub_bytes(state, INV_SBOX)
    state = _add_round_key(state, round_keys[0])
    return _from_state(state)


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    k = block - (len(data) % block)
    return data + bytes([k]) * k


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block != 0:
        raise ValueError("invalid padded length")
    k = data[-1]
    if k < 1 or k > block or data[-k:] != bytes([k]) * k:
        raise ValueError("invalid padding")
    return data[:-k]


# ---------------------------------------------------------------------------
# CBC mode (inter-block chaining around the 16-byte SPN primitive)
# ---------------------------------------------------------------------------

def cbc_encrypt(plaintext: bytes, round_keys, iv: bytes, progress_cb=None) -> bytes:
    data = pkcs7_pad(plaintext, 16)
    prev = iv
    out = bytearray()
    total_blocks = len(data) // 16
    for idx, i in enumerate(range(0, len(data), 16)):
        enc = encrypt_block(_xor(data[i:i + 16], prev), round_keys)
        out += enc
        prev = enc
        if progress_cb and (idx % 250 == 0 or idx == total_blocks - 1):
            progress_cb((idx + 1) / (total_blocks or 1))
    return bytes(out)


def cbc_decrypt(ciphertext: bytes, round_keys, iv: bytes, progress_cb=None) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext not a multiple of block size")
    prev = iv
    out = bytearray()
    total_blocks = len(ciphertext) // 16
    for idx, i in enumerate(range(0, len(ciphertext), 16)):
        block = ciphertext[i:i + 16]
        out += _xor(decrypt_block(block, round_keys), prev)
        prev = block
        if progress_cb and (idx % 250 == 0 or idx == total_blocks - 1):
            progress_cb((idx + 1) / (total_blocks or 1))
    return pkcs7_unpad(bytes(out), 16)
