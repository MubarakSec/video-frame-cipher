"""
Video-level pipeline for VFC.

The cryptographic + steganographic core (core.py) is self-contained and needs
only stdlib. This module adds the real "video in / video out" wrapper:

  * frame extraction        -> OpenCV (cv2)
  * audio demux / remux     -> ffmpeg (called as a subprocess)

The carrier video stream is copied LOSSLESSLY (-c:v copy) so the frame used for
key derivation is byte-identical on both sides, and the audio is stored as
uncompressed PCM (in an MKV container) so the LSB payload survives.
"""

import os
import subprocess
import tempfile

from .stego import WavAudio
from . import core


def _run(cmd):
    subprocess.run(cmd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def extract_frame_gray(video_path: str, frame_no: int):
    """Return frame `frame_no` as a 2D list of grayscale intensities."""
    import cv2  # lazy: the stdlib core must import without opencv installed

    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise RuntimeError(f"cannot open video: {video_path}")
    cap.set(cv2.CAP_PROP_POS_FRAMES, frame_no)
    ok, frame = cap.read()
    cap.release()
    if not ok:
        raise RuntimeError(f"cannot read frame {frame_no}")
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    return gray.tolist()


def _demux_audio(video_path: str, wav_path: str):
    _run(["ffmpeg", "-y", "-i", video_path, "-vn",
          "-acodec", "pcm_s16le", wav_path])


def _mux_audio(video_path: str, wav_path: str, out_path: str):
    # copy the video stream unchanged; replace audio with our PCM WAV
    _run(["ffmpeg", "-y", "-i", video_path, "-i", wav_path,
          "-map", "0:v:0", "-map", "1:a:0",
          "-c:v", "copy", "-c:a", "pcm_s16le", out_path])


def encrypt_video(in_video: str, secret_path: str, out_video: str,
                  password: bytes, frame_no: int, compress: bool = True, force: bool = False,
                  progress_cb=None):
    if progress_cb:
        progress_cb(0.02, f"Extracting frame #{frame_no} via OpenCV...")
    frame_gray = extract_frame_gray(in_video, frame_no)

    if progress_cb:
        progress_cb(0.06, "Reading secret file...")
    with open(secret_path, "rb") as f:
        secret = f.read()
    filename = os.path.basename(secret_path)

    with tempfile.TemporaryDirectory() as tmp:
        wav = os.path.join(tmp, "carrier.wav")
        stego_wav = os.path.join(tmp, "stego.wav")

        if progress_cb:
            progress_cb(0.10, "Demuxing PCM audio track (ffmpeg)...")
        _demux_audio(in_video, wav)

        if progress_cb:
            progress_cb(0.18, "Loading WAV samples...")
        audio = WavAudio.load(wav)

        def _core_cb(frac, msg):
            if progress_cb:
                progress_cb(0.20 + 0.65 * frac, msg)

        stats = core.encrypt(frame_gray, audio, secret, filename,
                             password, frame_no, compress, force=force,
                             progress_cb=_core_cb)

        if progress_cb:
            progress_cb(0.88, "Saving stego audio WAV...")
        audio.save(stego_wav)

        if progress_cb:
            progress_cb(0.92, "Losslessly multiplexing stego video (ffmpeg)...")
        _mux_audio(in_video, stego_wav, out_video)

        if progress_cb:
            progress_cb(1.0, "Done!")
    return stats


def decrypt_video(stego_video: str, out_dir: str,
                  password: bytes, frame_no: int,
                  progress_cb=None):
    if progress_cb:
        progress_cb(0.05, f"Extracting frame #{frame_no} via OpenCV...")
    frame_gray = extract_frame_gray(stego_video, frame_no)

    with tempfile.TemporaryDirectory() as tmp:
        wav = os.path.join(tmp, "stego.wav")
        if progress_cb:
            progress_cb(0.12, "Demuxing stego audio track (ffmpeg)...")
        _demux_audio(stego_video, wav)

        if progress_cb:
            progress_cb(0.20, "Loading audio samples...")
        audio = WavAudio.load(wav)

        def _core_cb(frac, msg):
            if progress_cb:
                progress_cb(0.22 + 0.73 * frac, msg)

        filename, data = core.decrypt(frame_gray, audio, password, frame_no,
                                      progress_cb=_core_cb)

    if progress_cb:
        progress_cb(0.96, f"Writing recovered file '{filename}'...")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, filename)
    with open(out_path, "wb") as f:
        f.write(data)

    if progress_cb:
        progress_cb(1.0, "Decryption complete!")
    return out_path
