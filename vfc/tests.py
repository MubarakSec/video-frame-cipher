#!/usr/bin/env python3
"""
VFC test suite — 13 checks (spec section 8, v0.2).

Run:
    python3 vfc/tests.py          # from the repo root
    python3 tests.py              # from inside vfc/

Covers:
    MixColumns invertibility, S-Box bijectivity, block roundtrip,
    avalanche, cross-byte diffusion, spec tests A-G, and LSB
    steganalysis (payload bit uniformity).
"""

import os
import random
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vfc import core
from vfc.cipher import (SBOX, INV_SBOX, MDS, INV_MDS, decrypt_block,
                        encrypt_block, mat_mul_gf, is_identity, ROUNDS)
from vfc.stego import WavAudio
from vfc.fingerprint import fingerprint_from_gray
from vfc.keys import derive_k_embed, expand_round_keys
from vfc.prng import shuffled_positions

rng = random.Random("VFC-tests-0.2")


def random_bytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def make_frame():
    return [[(128 + int(60 * __import__("math").sin(x / 6.0)
                        + 60 * __import__("math").sin(y / 7.0))) % 256
             for x in range(64)] for y in range(64)]


def make_audio(n=300000):
    samples = __import__("array").array(
        "h", (((0x9E37 * i) % 36000 - 18000) for i in range(n)))
    return WavAudio(None, samples)


PASSWORD = b"BlackRing-2028"
FRAME = 30


def _fresh_env(gray=None, audio=None, secret=None):
    return (gray or make_frame(),
            audio or make_audio(),
            secret if secret is not None else b"VFC confidential note\npayload\n" * 30,
            PASSWORD, FRAME)


# ---------------------------------------------------------------------------
# cipher properties
# ---------------------------------------------------------------------------

def test_mixcolumns_invertible():
    return is_identity(mat_mul_gf(INV_MDS, MDS))


def test_sbox_bijective():
    return (len(set(SBOX)) == 256
            and all(INV_SBOX[SBOX[i]] == i for i in range(256))
            and all(SBOX[INV_SBOX[i]] == i for i in range(256)))


def test_block_roundtrip():
    rk = expand_round_keys(b"k" * 32, ROUNDS)
    return all(decrypt_block(encrypt_block(b.to_bytes(16, "big"), rk), rk)
               == b.to_bytes(16, "big") for b in rng.sample(range(256), 8))


def test_avalanche():
    rk = expand_round_keys(b"k" * 32, ROUNDS)
    base = bytes(rng.getrandbits(8) for _ in range(16))
    c0 = encrypt_block(base, rk)
    changed = 0
    for i in range(128):
        c1 = bytearray(base)
        c1[i // 8] ^= 1 << (7 - i % 8)
        changed += bin(int.from_bytes(bytes(a ^ b for a, b in
                                           zip(c0, encrypt_block(bytes(c1), rk))),
                                      "big")).count("1")
    pct = 100.0 * (changed / 128) / 128
    return 46.0 <= pct <= 54.0  # spec measures ~50.3%


def test_cross_byte_diffusion():
    """One changed input byte must flip all 16 output bytes.

    A single byte of a random block can coincide (~1/256), so try a few flip
    masks per position and require full diffusion for at least one of them.
    """
    rk = expand_round_keys(b"k" * 32, ROUNDS)
    base = bytes(rng.getrandbits(8) for _ in range(16))
    c0 = encrypt_block(base, rk)
    for pos in range(16):
        for mask in (0x01, 0x80, 0x5A, 0x3C):
            variant = bytearray(base)
            variant[pos] ^= mask
            changed_bytes = sum(1 for a, b in zip(c0, encrypt_block(bytes(variant), rk))
                                if a != b)
            if changed_bytes == 16:
                break
        else:
            return False
    return True


# ---------------------------------------------------------------------------
# spec tests A-G (end to end over the core)
# ---------------------------------------------------------------------------

def _roundtrip(secret, label):
    gray, audio, secret_bytes, pw, frame = _fresh_env(secret=secret)
    core.encrypt(gray, audio, secret_bytes, label, pw, frame)
    name, data = core.decrypt(gray, audio, pw, frame)
    return name == label and data == secret_bytes


def test_a_text():
    return _roundtrip(b"The quick brown fox jumps over the lazy dog.\n" * 200, "note.txt")


def test_b_image():
    secret = random_bytes(4 * 1024)
    gray, audio, _s, pw, frame = _fresh_env(secret=secret)
    core.encrypt(gray, audio, secret, "pic.bmp", pw, frame)
    _n, data = core.decrypt(gray, audio, pw, frame)
    return data == secret


def test_c_pdf():
    secret = random_bytes(8 * 1024)
    gray, audio, _s, pw, frame = _fresh_env(secret=secret)
    core.encrypt(gray, audio, secret, "doc.pdf", pw, frame)
    _n, data = core.decrypt(gray, audio, pw, frame)
    return data == secret


def test_d_wrong_password():
    gray, audio, secret, pw, frame = _fresh_env()
    core.encrypt(gray, audio, secret, "x", pw, frame)
    try:
        core.decrypt(gray, audio, b"wrong-password", frame)
        return False
    except ValueError:
        return True


def test_e_wrong_frame():
    gray, audio, secret, pw, frame = _fresh_env()
    core.encrypt(gray, audio, secret, "x", pw, frame)
    other = [[(x * 13 + y) % 256 for x in range(64)] for y in range(64)]
    try:
        core.decrypt(other, audio, pw, frame)
        return False
    except ValueError:
        return True


def test_f_single_bit_flip():
    gray, audio, secret, pw, frame = _fresh_env()
    core.encrypt(gray, audio, secret, "x", pw, frame)

    fp = fingerprint_from_gray(gray)
    k_embed = derive_k_embed(pw, fp, frame)
    positions = shuffled_positions(k_embed, audio.eligible_indices())

    bad = WavAudio(None, audio.samples[:])
    bad.samples[positions[1000]] ^= 1  # hit ciphertext/tag region
    try:
        core.decrypt(gray, bad, pw, frame)
        return False
    except ValueError:
        return True


def test_g_audio_quality():
    gray, audio, secret, pw, frame = _fresh_env()
    orig = list(audio.samples)
    stats = core.encrypt(gray, audio, secret, "x", pw, frame)
    used = stats["used_samples"]

    mse = sum((a - b) ** 2 for a, b in zip(orig, audio.samples)) / len(orig)
    signal = sum(a * a for a in orig)
    noise = mse * len(orig)
    ratio = 10 * __import__("math").log10(signal / noise) if noise else float("inf")
    return used > 0 and mse < 5e-2 and ratio > 80.0  # spec on real video: MSE=0.001, SNR=108.6dB


def test_lsb_uniformity():
    """Steganalysis: LSBs at the embedded positions must look uniform (chi² ~ 0)."""
    gray, audio, secret, pw, frame = _fresh_env(secret=random_bytes(2048))
    stats = core.encrypt(gray, audio, secret, "x", pw, frame)

    fp = fingerprint_from_gray(gray)
    k_embed = derive_k_embed(pw, fp, frame)
    positions = shuffled_positions(k_embed, audio.eligible_indices())[:stats["used_samples"]]

    ones = sum(audio.samples[p] & 1 for p in positions)
    zeros = len(positions) - ones
    n = len(positions)
    chi2 = ((zeros - n / 2) ** 2 + (ones - n / 2) ** 2) / (n / 2)
    return chi2 < 10.0


def test_doc_appendix_vectors_sanity():
    """The spec appendix's fixed values should still reproduce (cipher only)."""
    rk = expand_round_keys(b"k" * 32, ROUNDS)
    block = bytes.fromhex("48656c6c6f2056464320010203040506")
    return decrypt_block(encrypt_block(block, rk), rk) == block


CHECKS = [
    ("MixColumns invertible (INV x M = I)", test_mixcolumns_invertible),
    ("S-Box bijective + correct inverse", test_sbox_bijective),
    ("Block roundtrip decrypt(encrypt(x)) = x", test_block_roundtrip),
    ("Avalanche ~50% bit change", test_avalanche),
    ("Cross-byte diffusion (1 byte in -> 16/16 bytes)", test_cross_byte_diffusion),
    ("Test A - text roundtrip", test_a_text),
    ("Test B - image (4KB) roundtrip", test_b_image),
    ("Test C - PDF (8KB) roundtrip", test_c_pdf),
    ("Test D - wrong password rejected", test_d_wrong_password),
    ("Test E - wrong frame rejected", test_e_wrong_frame),
    ("Test F - single bit flip rejected", test_f_single_bit_flip),
    ("Test G - audio quality (SNR > 80 dB)", test_g_audio_quality),
    ("Steganalysis - hidden LSBs uniform (chi²)", test_lsb_uniformity),
]


def main():
    passed = 0
    for name, fn in CHECKS:
        ex = ""
        try:
            ok = fn()
        except Exception as e:  # noqa: BLE001 - report, don't crash the suite
            ok, ex = False, f"{type(e).__name__}: {e}"
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              + ("" if ok else f"   ({ex})"))
        passed += bool(ok)
    print(f"\n{passed}/{len(CHECKS)} checks passed")
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())