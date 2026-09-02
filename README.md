# VFC — Video Frame Cipher (v0.2)

Educational cryptographic steganography. Encrypts a file with a custom block
cipher, then hides the ciphertext inside a video's audio track. The encryption
keys are derived from a chosen **video frame + password**, so the carrier video
is both the hiding place and part of the key context.

> Educational project. The custom cipher has not undergone professional
> cryptanalysis and must not be used to protect real secrets. Building and using
> covert channels can carry legal consequences; keep this inside the coursework.

## Layout

```
vfc/
  cipher.py       GF(2^8), S-Box, SPN block cipher (SubBytes/ShiftRows/MixColumns/AddRoundKey), CBC, PKCS#7
  keys.py         PBKDF2 key derivation (salt-separated K_embed), key-derived magic, round-key schedule, HMAC
  prng.py         SHA-256 counter keystream + Fisher-Yates position selection
  fingerprint.py  frame -> grayscale -> 32x32 -> 8x8 blocks -> median threshold -> 64-bit fingerprint
  stego.py        16-bit PCM WAV I/O, sample eligibility, LSB embed/extract
  payload.py      payload format + HMAC authentication + length sanity check
  core.py         encrypt/decrypt orchestration (frame array + WAV)
  video.py        real video pipeline: frame via OpenCV, audio demux/mux via ffmpeg
vfc_cli.py        command-line interface
tests.py          test suite (spec tests A–G + cipher properties + steganalysis)
demo_video.py     end-to-end demo on a real video file
trace.py          step-by-step block cipher CLI tracer
trace_gui.py      interactive, sophisticated block cipher GUI & math visualizer
```

## Requirements

- Python 3.8+
- `opencv-python-headless`, `ffmpeg` (only for the video wrapper; the core needs only stdlib)

## Setup

Create the virtual environment and install the video dependency:

```bash
python3 -m venv .venv
.venv/bin/pip install opencv-python-headless
```

## Graphical User Interface (GUI)

Launch the easy-to-use desktop GUI:

```bash
.venv/bin/python vfc_gui.py
# or
.venv/bin/python vfc/vfc_cli.py gui
```

Features included in the GUI:
- 🔒 **Interactive Encryption**: Select carrier video, choose any secret file, scrub frames with **real-time visual preview** and computed 64-bit fingerprint, with instant progress & capacity stats.
- 🔓 **One-Click Decryption**: Select stego video, input password & frame, and automatically recover the secret file with direct folder/file open shortcuts.
- 🛠️ **Carrier Converter & Capacity Tools**: Convert MP4/MOV to lossless MKV/PCM carrier and analyze audio steganography capacity.
- 📜 **Live Activity Console**: Real-time logging of encryption steps and status.

## Command Line Usage

```bash
# make a carrier with a lossless-PCM audio track (MKV recommended)
ffmpeg -i input.mp4 -c:v copy -c:a pcm_s16le carrier.mkv

export VFC_PASSWORD='your password'

.venv/bin/python vfc/vfc_cli.py encrypt -i carrier.mkv -s secret.pdf -o stego.mkv -f 30
.venv/bin/python vfc/vfc_cli.py decrypt -i stego.mkv  -o recovered/          -f 30
```

## Tests

```bash
.venv/bin/python vfc/tests.py            # 13/13 checks
.venv/bin/python vfc/demo_video.py /tmp/carrier.mkv
```

## Key design decisions (v0.2)

1. **Salt circular dependency fixed** — `K_embed` is derived *without* the salt,
   so the payload (which stores the salt) can be located before the salt is known.
2. **Cross-byte diffusion added** — MixColumns over GF(2^8) (verified invertible)
   removes the original per-byte independence; avalanche ≈ 50%.
3. **Key-derived magic** — no free password oracle at the payload head.
4. **Silence-safe, embed-stable eligibility** — `abs(sample >> 1) >= T`.
5. **CSPRNG positions** — SHA-256 counter stream + Fisher-Yates (no reused samples).
6. **Authenticated** — HMAC-SHA256 over header+ciphertext, constant-time compare.
7. **Honest threat model** — the frame provides key diversification, not secrecy;
   the password is the only secret.
