#!/usr/bin/env python3
"""
VFC Step-by-Step Cipher Tracer & Deep Mathematical Explainer (v0.2)
Standalone, zero-dependency script for inspecting and verifying the VFC block cipher.

Features:
- Traces every round and every SPN layer (SubBytes, ShiftRows, MixColumns, AddRoundKey).
- Supports VFC Key Expansion Schedule (SHA-256 domain separation: RK_i = SHA256(K_enc || "VFC-RK" || i)[:16]).
- Supports --detailed mode with step-by-step GF(2^8) Galois Field arithmetic, S-Box lookups, and row shifts.
- Supports hand-tracing with --zero-key (all-zero round subkeys).

Usage:
    python3 trace.py                      # traces "Hello" with VFC key expansion
    python3 trace.py "SECRET"             # traces custom word
    python3 trace.py "SECRET" mysecretkey # traces with custom key
    python3 trace.py --detailed           # includes deep mathematical breakdown of Round 1
    python3 trace.py --zero-key           # uses all-zero key for easy pen-and-paper tracing
"""

import sys
import argparse
import hashlib

# ---------------------------------------------------------------------------
# GF(2^8) arithmetic (Rijndael field, irreducible polynomial 0x11B)
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
            a ^= 0x1B  # reduction step (x^8 = x^4 + x^3 + x + 1)
        b >>= 1
    return p


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

ROUNDS = 6


# ---------------------------------------------------------------------------
# S-Box (fixed public bijective substitution built from SHA-256)
# ---------------------------------------------------------------------------
def _build_sbox(seed: bytes):
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


# ---------------------------------------------------------------------------
# Key Schedule / Expansion (Section 18 & vfc/keys.py)
# ---------------------------------------------------------------------------
def expand_round_keys(k_enc: bytes, rounds: int = ROUNDS):
    """
    Derives (rounds + 1) distinct 16-byte round keys using domain separation:
        RK_i = SHA-256(K_enc || "VFC-RK" || uint16_be(i))[0:16]
    """
    return [
        hashlib.sha256(k_enc + b"VFC-RK" + i.to_bytes(2, "big")).digest()[:16]
        for i in range(rounds + 1)
    ]


# ---------------------------------------------------------------------------
# State helpers (16 bytes <-> 4x4 column-major grid, like AES)
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
    return [state[r][r:] + state[r][:r] for r in range(4)]


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


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    k = block - (len(data) % block)
    return data + bytes([k]) * k


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------
def show_state(label: str, state, note: str = ""):
    print(f"  {label}")
    for r in range(4):
        row = "  ".join(f"{state[r][c]:02x}" for c in range(4))
        print(f"      {row}")
    if note:
        print(f"      -> hex: {_from_state(state).hex()}   ({note})")
    print()


def explain_round_1_math(state_in, state_sub, state_shift, state_mix, state_out, rk1):
    """Deep mathematical walkthrough of Round 1 operations."""
    print("  " + "=" * 60)
    print("  [DEEP MATH BREAKDOWN: ROUND 1]")
    print("  " + "=" * 60)

    # 1. SubBytes Lookups
    print("  1) SubBytes (Non-linear Confusion):")
    print("     Replaces every byte b with SBOX[b]:")
    for r in range(2):
        for c in range(2):
            in_b = state_in[r][c]
            out_b = state_sub[r][c]
            print(f"       state[{r}][{c}]: 0x{in_b:02x} -> SBOX[0x{in_b:02x}] = 0x{out_b:02x}")
    print("       ... (and similarly for all 16 state cells)\n")

    # 2. ShiftRows Rotations
    print("  2) ShiftRows (Inter-Column Diffusion):")
    print("     Cyclically shifts row r left by r bytes:")
    for r in range(4):
        old_row = " ".join(f"{state_sub[r][c]:02x}" for c in range(4))
        new_row = " ".join(f"{state_shift[r][c]:02x}" for c in range(4))
        print(f"       Row {r} (rot left by {r}): [{old_row}] -> [{new_row}]")
    print()

    # 3. MixColumns GF(2^8) Matrix Multiplication
    print("  3) MixColumns (Intra-Column Diffusion in GF(2^8)):")
    print("     Multiplies each column by the MDS circulant matrix [2, 3, 1, 1].")
    print("     Detailed step-by-step for Column 0:")
    col0 = [state_shift[i][0] for i in range(4)]
    print(f"       Column 0 input vector: [0x{col0[0]:02x}, 0x{col0[1]:02x}, 0x{col0[2]:02x}, 0x{col0[3]:02x}]^T")
    
    # Calculate row 0 of column 0
    t0 = gmul(2, col0[0])
    t1 = gmul(3, col0[1])
    t2 = gmul(1, col0[2])
    t3 = gmul(1, col0[3])
    res0 = t0 ^ t1 ^ t2 ^ t3
    print(f"       s'[0,0] = (2 * 0x{col0[0]:02x}) ^ (3 * 0x{col0[1]:02x}) ^ (1 * 0x{col0[2]:02x}) ^ (1 * 0x{col0[3]:02x})")
    print(f"               = 0x{t0:02x} ^ 0x{t1:02x} ^ 0x{t2:02x} ^ 0x{t3:02x}")
    print(f"               = 0x{res0:02x} (matches state[0][0] after MixColumns)\n")

    # 4. AddRoundKey
    print("  4) AddRoundKey (Key Mixing):")
    print("     Bitwise XOR of state with Round Key RK1:")
    rk1_state = _to_state(rk1)
    for r in range(2):
        c = 0
        s_val = state_mix[r][c]
        k_val = rk1_state[r][c]
        out_val = state_out[r][c]
        print(f"       state[{r}][{c}] = 0x{s_val:02x} ^ RK1[{r}][{c}] (0x{k_val:02x}) = 0x{out_val:02x}")
    print("  " + "=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="VFC Step-by-Step Block Cipher Tracer & Math Explainer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 trace.py
  python3 trace.py "SECRET"
  python3 trace.py "SECRET" "my_demo_password"
  python3 trace.py --detailed
  python3 trace.py --zero-key
        """
    )
    parser.add_argument("word", nargs="?", default="Hello", help="Plaintext word to trace (default: 'Hello')")
    parser.add_argument("key", nargs="?", default=None, help="Master key (ASCII string or 32/64 hex chars)")
    parser.add_argument("--detailed", "-d", action="store_true", help="Print deep mathematical breakdown for Round 1")
    parser.add_argument("--zero-key", "-z", action="store_true", help="Use all-zero subkeys for simple hand-tracing")
    parser.add_argument("--gui", "-g", action="store_true", help="Launch interactive graphical cipher tracer GUI")

    args = parser.parse_args()

    if args.gui:
        try:
            from trace_gui import launch_trace_gui
            launch_trace_gui()
            return
        except Exception as e:
            print(f"[!] Error launching GUI: {e}")
            sys.exit(1)

    word = args.word
    plaintext = word.encode("utf-8")
    padded = pkcs7_pad(plaintext, 16)

    # 1. Determine Master Key & Round Keys
    if args.zero_key:
        round_keys = [bytes(16)] * (ROUNDS + 1)
        key_mode = "All-zero static subkeys (--zero-key, ideal for hand-tracing)"
    else:
        if args.key is None:
            master_key_bytes = hashlib.sha256(b"VFC-DEMO-MASTER-KEY").digest()
            key_mode = "VFC-DEMO-MASTER-KEY (SHA-256 expanded)"
        else:
            raw_key = args.key
            if len(raw_key) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in raw_key):
                master_key_bytes = bytes.fromhex(raw_key)
            else:
                master_key_bytes = hashlib.sha256(raw_key.encode("utf-8")).digest()
            key_mode = f"Custom master key: '{raw_key}' (32 bytes)"

        round_keys = expand_round_keys(master_key_bytes, ROUNDS)

    IV = bytes(16)

    print("=" * 70)
    print(f" VFC CIPHER TRACE & DEEP DIVE  —  Input: {word!r}")
    print(f" Mode: {key_mode}")
    print(f" Cipher: SPN 128-bit block, {ROUNDS} rounds, CBC Mode (IV: {IV.hex()})")
    print("=" * 70)

    # 2. Key Expansion Schedule Table
    print("\n--- KEY SCHEDULE (Round Keys RK0 .. RK6) ---")
    print(" Formula: RK_i = SHA-256(K_enc || 'VFC-RK' || uint16_be(i))[0:16]")
    for i, rk in enumerate(round_keys):
        label = "RK0 (Initial Whitening)" if i == 0 else f"RK{i} (Round {i} Key)"
        print(f"   {label:<24}: {rk.hex()}")
    print()

    # 3. Plaintext & Initial Padding
    print("--- [0] PLAINTEXT & PKCS#7 PADDING ---")
    print(f"  Plaintext string : {word!r}")
    print(f"  Plaintext bytes  : {plaintext}")
    print(f"  Padded 16-byte   : {padded.hex()}")
    print(f"  Padding applied  : {padded[-1]} bytes of value 0x{padded[-1]:02x}")

    block = _xor(padded, IV)
    print("\n--- [1] CBC INPUT BLOCK (Padded XOR IV) ---")
    print(f"  Block bytes hex  : {block.hex()}\n")

    # 4. Initial Whitening
    state = _to_state(block)
    state = _add_round_key(state, round_keys[0])
    show_state("Initial Whitening (AddRoundKey with RK0):", state, "XOR with RK0")

    # 5. Encryption Rounds
    for r in range(1, ROUNDS + 1):
        print(f"------ ROUND {r} " + "-" * 56)
        state_in = [row[:] for row in state]

        state_sub = _sub_bytes(state, SBOX)
        show_state("SubBytes   (S-Box Non-Linear Substitution):", state_sub, "Confusion")

        state_shift = _shift_rows(state_sub)
        show_state("ShiftRows  (Row r Cyclically Rotated Left by r):", state_shift, "Inter-column Diffusion")

        state_mix = _mix_columns(state_shift, MDS)
        show_state("MixColumns (GF(2^8) Matrix Multiplication):", state_mix, "Intra-column Diffusion")

        state_out = _add_round_key(state_mix, round_keys[r])
        show_state(f"AddRoundKey (XOR with RK{r}):", state_out, "Key Mixing")

        if r == 1 and (args.detailed or args.zero_key):
            explain_round_1_math(state_in, state_sub, state_shift, state_mix, state_out, round_keys[1])

        state = state_out

    ct = _from_state(state)
    print("=" * 70)
    print(f" FINAL CIPHERTEXT BLOCK (Hex): {ct.hex()}")
    print("=" * 70)


if __name__ == "__main__":
    main()

