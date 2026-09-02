# VFC — Video Frame Cipher

> Educational cryptographic steganography system. Encrypts a file with a custom SPN block cipher, then hides the ciphertext inside a video's audio track. The carrier video is both the hiding place and part of the key context.

**v0.2** | Python 3.8+

> **Warning:** The custom cipher has not undergone professional cryptanalysis and must not be used to protect real secrets. Building and using covert channels can carry legal consequences — keep this inside coursework.

---

## How It Works

```
┌─────────────┐     ┌──────────┐     ┌──────────────┐     ┌─────────────┐
│ Secret File  │────▶│ SPN CBC  │────▶│ Payload +    │────▶│ LSB Embed   │
│              │     │ Encrypt  │     │ HMAC-SHA256  │     │ into Audio  │
└─────────────┘     └──────────┘     └──────────────┘     └─────────────┘
                          ▲                                      │
                          │                                      ▼
                   ┌──────┴──────┐                       ┌──────────────┐
                   │ Frame +     │                       │ Stego Video  │
                   │ Password    │                       │ (MKV+PCM)    │
                   │ → PBKDF2    │                       └──────────────┘
                   └─────────────┘
```

The password is the only secret. The video frame provides **key diversification** (binding the operation to a specific carrier), not secrecy.

## Project Structure

```
vfc/
  cipher.py       GF(2^8) arithmetic, S-Box, SPN block cipher (SubBytes/ShiftRows/MixColumns/AddRoundKey), CBC, PKCS#7
  keys.py         PBKDF2 key derivation (salt-separated K_embed), key-derived magic, round-key schedule, HMAC
  prng.py         SHA-256 counter keystream + Fisher-Yates position selection
  fingerprint.py  frame → grayscale → 32×32 → 8×8 blocks → median threshold → 64-bit fingerprint
  stego.py        16-bit PCM WAV I/O, sample eligibility, LSB embed/extract
  payload.py      payload format + HMAC authentication + length sanity check
  core.py         encrypt/decrypt orchestration (frame array + WAV)
  video.py        real video pipeline: frame via OpenCV, audio demux/mux via ffmpeg
  gui.py          modern desktop GUI with real-time frame preview and progress tracking
  tests.py        13-check test suite (spec tests A–G + cipher properties + steganalysis)
  demo_video.py   end-to-end demo on a real video file
vfc_cli.py        command-line interface
vfc_gui.py        GUI launcher
trace.py          step-by-step block cipher CLI tracer
trace_gui.py      interactive block cipher visualizer & math inspector
generate_vfc_trace.py  deterministic teaching-vector generator for the academic kit
academic-kit/     React/TypeScript interactive visualizations (Arabic)
```

## Quick Start

```bash
# Clone
git clone <your-repo-url> && cd Crypto

# Setup
python3 -m venv .venv
.venv/bin/pip install opencv-python-headless
```

## GUI

```bash
.venv/bin/python vfc_gui.py
```

**Features:**
- Encrypt & hide any file inside a video carrier with real-time frame preview and 64-bit fingerprint display
- One-click decryption with automatic file recovery
- Carrier converter (MP4/MOV → lossless MKV/PCM)
- Audio steganography capacity inspector
- Live activity log console

## Command Line

```bash
# Create a carrier with lossless PCM audio (MKV recommended)
ffmpeg -i input.mp4 -c:v copy -c:a pcm_s16le carrier.mkv

export VFC_PASSWORD='your password'

# Encrypt
.venv/bin/python vfc/vfc_cli.py encrypt -i carrier.mkv -s secret.pdf -o stego.mkv -f 30

# Decrypt
.venv/bin/python vfc/vfc_cli.py decrypt -i stego.mkv -o recovered/ -f 30
```

## Block Cipher Tracer

Byte-by-byte visualization of the SPN cipher with deep GF(2^8) math breakdowns:

```bash
.venv/bin/python trace.py                     # trace "Hello" with default key
.venv/bin/python trace.py "SECRET"            # trace custom plaintext
.venv/bin/python trace.py --detailed          # includes Round 1 math explainer
.venv/bin/python trace.py --gui               # launch interactive GUI tracer
```

## Tests

```bash
.venv/bin/python vfc/tests.py    # 13/13 checks
```

Runs MixColumns invertibility, S-Box bijectivity, block roundtrip, avalanche, cross-byte diffusion, end-to-end spec tests A–G (text/image/PDF roundtrip, wrong password, wrong frame, single bit flip, audio quality), and LSB steganalysis.

## Key Design Decisions (v0.2)

| Decision | Detail |
|---|---|
| **Salt circular dependency fixed** | `K_embed` is derived *without* the salt, so the payload (which stores the salt) can be located before the salt is known |
| **Cross-byte diffusion** | MixColumns over GF(2^8) (MDS matrix, verified invertible) removes per-byte independence; avalanche ≈ 50% |
| **Key-derived magic** | 4-byte payload marker from `K_embed` — no free password oracle |
| **Silence-safe eligibility** | `abs(sample >> 1) >= T` makes eligibility invariant under LSB replacement |
| **CSPRNG positions** | SHA-256 counter stream + Fisher-Yates shuffle (no reused samples) |
| **Authenticated** | HMAC-SHA256 over header+ciphertext, constant-time comparison |
| **Honest threat model** | Frame provides key diversification, not secrecy; password is the only secret |

## Requirements

- **Python 3.8+**
- **Core** (encrypt/decrypt/test): stdlib only
- **Video pipeline**: `opencv-python-headless` + `ffmpeg`
- **GUI**: `tkinter` (usually bundled with Python)

## License

Academic / coursework project. Not licensed for production use.
