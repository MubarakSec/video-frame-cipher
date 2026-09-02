"""
End-to-end demo on a REAL video file.

  carrier.mkv  +  secret.txt  --VFC-->  stego.mkv
  stego.mkv    --VFC-->  recovered secret.txt

Run:  python3 demo_video.py /tmp/carrier.mkv
"""

import sys
import hashlib
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vfc import video

CARRIER = sys.argv[1] if len(sys.argv) > 1 else "/tmp/carrier.mkv"
PASSWORD = b"BlackRing-2028"
FRAME = 30

SECRET_PATH = "/tmp/secret.txt"
STEGO = "/tmp/stego.mkv"
OUT_DIR = "/tmp/vfc_out"


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


def main():
    with open(SECRET_PATH, "w") as f:
        f.write("VFC confidential note\n" + "payload line\n" * 50)

    print("Carrier :", CARRIER)
    print("Secret  :", SECRET_PATH, "sha=", sha(SECRET_PATH))
    print("Frame N :", FRAME)

    stats = video.encrypt_video(CARRIER, SECRET_PATH, STEGO, PASSWORD, FRAME)
    print("\nEncrypted -> ", STEGO)
    for k, v in stats.items():
        print(f"   {k:18} {v}")

    out = video.decrypt_video(STEGO, OUT_DIR, PASSWORD, FRAME)
    print("\nDecrypted -> ", out, "sha=", sha(out))
    print("MATCH:", sha(out) == sha(SECRET_PATH))

    # wrong password must fail
    try:
        video.decrypt_video(STEGO, OUT_DIR, b"wrong", FRAME)
        print("wrong password: UNEXPECTED SUCCESS")
    except ValueError:
        print("wrong password: correctly rejected")


if __name__ == "__main__":
    main()
