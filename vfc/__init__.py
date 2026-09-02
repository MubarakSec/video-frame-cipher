"""
VFC - Video Frame Cipher (v0.2)

Educational cryptographic steganography: hide an encrypted file inside a
video's audio track, with keys derived from a chosen video frame + password.

Public API:
    core.encrypt / core.decrypt          -> operate on a frame array + WavAudio
    video.encrypt_video / decrypt_video  -> operate on real video files
"""

from . import core, video, cipher, keys, prng, fingerprint, stego, payload

__all__ = ["core", "video", "cipher", "keys", "prng", "fingerprint", "stego", "payload"]
__version__ = "0.2"
