#!/usr/bin/env python3
"""
VFC Graphical User Interface Launcher.

Run with:
    python3 vfc_gui.py
or:
    .venv/bin/python vfc_gui.py
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Auto-detect and re-exec inside .venv if dependencies (like cv2) are only in .venv
venv_python = os.path.join(BASE_DIR, ".venv", "bin", "python")
try:
    import cv2
except ImportError:
    if os.path.isfile(venv_python) and sys.executable != venv_python:
        os.execv(venv_python, [venv_python] + sys.argv)

from vfc.gui import launch_gui

if __name__ == "__main__":
    try:
        launch_gui()
    except KeyboardInterrupt:
        print("\nVFC GUI closed.")
        sys.exit(0)
