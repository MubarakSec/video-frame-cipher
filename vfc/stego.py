"""
Audio LSB steganography on 16-bit PCM WAV (spec sections 21-25).

Fixes from review:

* Sample eligibility (section 24 was undefined).
  Digital silence has near-constant LSBs; writing random bits there is visible
  on a waveform. We embed only in samples whose magnitude (ignoring the LSB) is
  above a threshold:  abs(sample >> 1) >= THRESHOLD.
  Using `sample >> 1` makes eligibility INVARIANT under LSB replacement (the
  bit we flip is discarded by the shift), so the embedder and extractor always
  agree on the eligible set even though the audio changed between them.

* LSB *replacement* is used for VFC v1 (simple, easy to explain). LSB
  *matching* (+/-1) is documented as a future enhancement.
"""

import wave
import array

THRESHOLD = 2  # excludes near-silence; see module docstring for the >>1 trick.


# ---------------------------------------------------------------------------
# WAV I/O  (16-bit PCM, mono or stereo; channels handled as one flat stream)
# ---------------------------------------------------------------------------

class WavAudio:
    def __init__(self, params, samples):
        self.params = params                 # wave._wave_params
        self.samples = samples               # array('h') of signed 16-bit ints

    @classmethod
    def load(cls, path):
        with wave.open(path, "rb") as w:
            params = w.getparams()
            if params.sampwidth != 2:
                raise ValueError("VFC requires 16-bit PCM audio")
            raw = w.readframes(params.nframes)
        samples = array.array("h")
        samples.frombytes(raw)
        return cls(params, samples)

    def save(self, path):
        with wave.open(path, "wb") as w:
            w.setparams(self.params)
            w.writeframes(self.samples.tobytes())

    def eligible_indices(self):
        return [i for i, s in enumerate(self.samples) if abs(s >> 1) >= THRESHOLD]

    def capacity_bits(self):
        return len(self.eligible_indices())


# ---------------------------------------------------------------------------
# bit <-> byte helpers  (MSB first, consistent both directions)
# ---------------------------------------------------------------------------

def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def bits_to_bytes(bits) -> bytes:
    out = bytearray()
    acc = 0
    n = 0
    for bit in bits:
        acc = (acc << 1) | (bit & 1)
        n += 1
        if n == 8:
            out.append(acc)
            acc = 0
            n = 0
    return bytes(out)


# ---------------------------------------------------------------------------
# embed / extract
# ---------------------------------------------------------------------------

def embed(audio: WavAudio, payload: bytes, positions, force: bool = False, progress_cb=None):
    """LSB-replace payload bits into `audio.samples` at the given positions.
    If `force=True`, embeds as many bits as fit and truncates the rest (for demo).
    """
    bits = list(bytes_to_bits(payload))
    if len(bits) > len(positions) and not force:
        raise ValueError("payload larger than available positions")
    samples = audio.samples
    total = min(len(bits), len(positions))
    for i, (bit, pos) in enumerate(zip(bits, positions)):
        s = samples[pos]
        samples[pos] = (s & ~1) | bit
        if progress_cb and (i % 50000 == 0 or i == total - 1):
            progress_cb((i + 1) / (total or 1))


def extract(audio: WavAudio, positions, nbits: int, progress_cb=None) -> bytes:
    """Read `nbits` LSBs from `positions` (in order) and pack to bytes."""
    samples = audio.samples

    def _gen():
        for i in range(nbits):
            if progress_cb and (i % 50000 == 0 or i == nbits - 1):
                progress_cb((i + 1) / (nbits or 1))
            yield samples[positions[i]] & 1

    return bits_to_bytes(_gen())
