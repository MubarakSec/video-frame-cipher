"""
Frame fingerprint (spec section 8).

Turns one video frame into 64 bits (8 bytes) of compact, reproducible key
material. This is an average-hash (aHash): coarse enough to be stable, fine
enough to differ between distinct frames.

    frame -> grayscale -> 32x32 -> 8x8 blocks (64 blocks)
          -> per-block average -> median threshold -> 64 bits

Reminder (threat model): this value is NOT secret. It binds the keys to the
carrier video; the password provides the actual secret entropy.
"""

import statistics

GRID = 32     # normalized side length
BLOCKS = 8    # blocks per side -> 64 blocks -> 64 bits


def _nearest_resize(gray, out_h, out_w):
    """Pure-Python nearest-neighbour resize of a 2D list of ints."""
    in_h = len(gray)
    in_w = len(gray[0])
    out = [[0] * out_w for _ in range(out_h)]
    for y in range(out_h):
        sy = min(in_h - 1, y * in_h // out_h)
        row_in = gray[sy]
        row_out = out[y]
        for x in range(out_w):
            sx = min(in_w - 1, x * in_w // out_w)
            row_out[x] = row_in[sx]
    return out


def fingerprint_from_gray(gray) -> bytes:
    """`gray`: 2D list (rows x cols) of 0..255 intensities. Returns 8 bytes."""
    g = _nearest_resize(gray, GRID, GRID)
    step = GRID // BLOCKS  # 4

    averages = []
    for by in range(BLOCKS):
        for bx in range(BLOCKS):
            total = 0
            for y in range(by * step, by * step + step):
                row = g[y]
                for x in range(bx * step, bx * step + step):
                    total += row[x]
            averages.append(total / (step * step))

    median = statistics.median(averages)
    bits = [1 if a >= median else 0 for a in averages]

    out = bytearray(8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)
