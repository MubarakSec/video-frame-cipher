"""
Deterministic position generator for steganographic embedding.

Two decisions from review:

1. PRNG.  Do NOT use Python's random module (Mersenne Twister state is
   recoverable from its output). Instead use a SHA-256 counter stream keyed by
   K_embed:  block_i = SHA256(K_embed || counter_i). This is a simple, clean,
   cryptographically-flavoured keystream that needs no external library.

2. Fisher-Yates.  The stream drives an unbiased Fisher-Yates shuffle of the
   eligible sample indices. Consuming the shuffled list in order guarantees
   every position is unique (no two payload bits land on the same sample),
   which section 24 of the spec requires.
"""

import hashlib


class KeyStream:
    """Endless byte stream: SHA256(key || counter), counter = 0,1,2,..."""

    def __init__(self, key: bytes):
        self.key = key
        self.counter = 0
        self.buf = b""
        self.pos = 0

    def _refill(self):
        self.buf = hashlib.sha256(self.key + self.counter.to_bytes(8, "big")).digest()
        self.counter += 1
        self.pos = 0

    def byte(self) -> int:
        if self.pos >= len(self.buf):
            self._refill()
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def below(self, n: int) -> int:
        """Unbiased integer in [0, n) via rejection sampling (n <= 2^32)."""
        if n <= 1:
            return 0
        # smallest number of bytes that can hold n-1
        nbytes = 1
        while (1 << (8 * nbytes)) < n:
            nbytes += 1
        span = 1 << (8 * nbytes)
        bound = span - (span % n)
        while True:
            val = 0
            for _ in range(nbytes):
                val = (val << 8) | self.byte()
            if val < bound:
                return val % n


def shuffled_positions(key: bytes, eligible, progress_cb=None):
    """Return a deterministic permutation of `eligible` driven by `key`."""
    idx = list(eligible)
    stream = KeyStream(key)
    n = len(idx)
    for i in range(n - 1, 0, -1):
        j = stream.below(i + 1)
        idx[i], idx[j] = idx[j], idx[i]
        if progress_cb and ((n - i) % 100000 == 0 or i == 1):
            progress_cb((n - i) / (n or 1))
    return idx
