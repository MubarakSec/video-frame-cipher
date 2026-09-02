#!/usr/bin/env python3
"""
VFC command-line and graphical interface.

GUI:
    python3 vfc_cli.py gui   (or python3 vfc_gui.py)

Encrypt:
    python3 vfc_cli.py encrypt -i carrier.mkv -s secret.pdf -o stego.mkv -f 30

Decrypt:
    python3 vfc_cli.py decrypt -i stego.mkv -o out_dir -f 30

Password is read from the VFC_PASSWORD environment variable, or prompted.
The carrier must have an uncompressed-PCM-capable container (MKV recommended);
the video stream is copied losslessly so frame N is identical on both sides.
"""

import argparse
import getpass
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

venv_python = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")
try:
    import cv2
except ImportError:
    if os.path.isfile(venv_python) and sys.executable != venv_python:
        os.execv(venv_python, [venv_python] + sys.argv)

from vfc import video


def get_password():
    pw = os.environ.get("VFC_PASSWORD")
    if pw is None:
        pw = getpass.getpass("VFC password: ")
    return pw.encode("utf-8")


def main():
    if len(sys.argv) == 1:
        # Default to launching GUI if no CLI args passed
        try:
            from vfc.gui import launch_gui
            launch_gui()
            return
        except Exception as ex:
            print("Note: GUI could not be launched automatically:", ex)

    ap = argparse.ArgumentParser(prog="vfc")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gui", help="launch graphical user interface")

    e = sub.add_parser("encrypt", help="hide a file inside a video")
    e.add_argument("-i", "--input", required=True, help="carrier video")
    e.add_argument("-s", "--secret", required=True, help="file to hide")
    e.add_argument("-o", "--output", required=True, help="output stego video")
    e.add_argument("-f", "--frame", type=int, required=True, help="frame number")
    e.add_argument("--no-compress", action="store_true")
    e.add_argument("-F", "--force", action="store_true", help="force embedding even if payload exceeds audio capacity (for educational demo)")

    d = sub.add_parser("decrypt", help="recover a hidden file from a video")
    d.add_argument("-i", "--input", required=True, help="stego video")
    d.add_argument("-o", "--output", required=True, help="output directory")
    d.add_argument("-f", "--frame", type=int, required=True, help="frame number")

    args = ap.parse_args()

    if args.cmd == "gui":
        from vfc.gui import launch_gui
        launch_gui()
        return

    pw = get_password()

    if args.cmd == "encrypt":
        stats = video.encrypt_video(args.input, args.secret, args.output,
                                    pw, args.frame, compress=not args.no_compress, force=args.force)
        print("OK ->", args.output)
        for k, v in stats.items():
            print(f"  {k}: {v}")
    elif args.cmd == "decrypt":
        try:
            out = video.decrypt_video(args.input, args.output, pw, args.frame)
            print("OK ->", out)
        except (ValueError, RuntimeError) as ex:
            print("FAILED:", ex, file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
