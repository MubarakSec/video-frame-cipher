"""
VFC GUI - Modern Desktop Interface for Video Frame Cipher (v0.2).

Provides an easy-to-use graphical user interface for:
  * Encrypting & embedding files into video carriers with real-time percentage progress bar.
  * Extracting & decrypting hidden files from stego videos with progress feedback.
  * Force-embedding large files into small carriers for educational demos.
  * Converting arbitrary videos (MP4/MOV/etc.) to VFC-compatible MKV/PCM carriers.
  * Inspecting carrier audio capacity and video frame fingerprints.
"""

import os
import sys
import threading
import subprocess
import tempfile
import time
import tkinter as tk
import webbrowser
from tkinter import ttk, filedialog, messagebox
import cv2

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from vfc import video
from vfc.fingerprint import fingerprint_from_gray
from vfc.stego import WavAudio


def open_in_file_manager(path: str):
    """Open the directory or file in the native file manager."""
    target = path
    if os.path.isfile(target):
        target = os.path.dirname(target)
    if not os.path.exists(target):
        return
    try:
        if sys.platform == "win32":
            os.startfile(target)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", target])
        else:
            subprocess.Popen(["xdg-open", target])
    except Exception as ex:
        print(f"Error opening folder {target}: {ex}")


def open_file_directly(path: str):
    """Open the file in the default application."""
    if not os.path.isfile(path):
        return
    try:
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as ex:
        print(f"Error opening file {path}: {ex}")


def format_size(num_bytes: int) -> str:
    """Format bytes into human-readable string."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB"
    else:
        return f"{num_bytes / (1024 * 1024):.2f} MB"


class VfcGuiApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("VFC — Video Frame Cipher Studio (v0.2)")
        self.geometry("980x820")
        self.minsize(880, 720)

        # Restrained forensic-workbench palette shared with the academic kit.
        self.colors = {
            "bg": "#10100f",
            "surface": "#171713",
            "surface2": "#22221d",
            "surface3": "#2d2b25",
            "text": "#f7f3e8",
            "subtext": "#c7bead",
            "accent": "#c9aa75",
            "accent_hover": "#e2c68f",
            "success": "#78c58f",
            "warning": "#e1b85d",
            "error": "#e16a5f",
            "input_bg": "#0b0b0a",
            "border": "#565143",
        }

        self.configure(bg=self.colors["bg"])
        self._apply_theme()

        # State tracking
        self.enc_video_meta = {"path": "", "frames": 0, "fps": 0.0, "w": 0, "h": 0}
        self.dec_video_meta = {"path": "", "frames": 0, "fps": 0.0, "w": 0, "h": 0}
        self._preview_cache = {}  # (path, frame) -> (photo_image, fp_hex)
        self._debounce_timer = None
        self._academic_process = None

        self._build_ui()

    def _apply_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        c = self.colors

        # General styles
        style.configure(".",
            background=c["bg"],
            foreground=c["text"],
            troughcolor=c["input_bg"],
            focuscolor=c["accent"],
            font=("Segoe UI", 10)
        )

        # Frame
        style.configure("TFrame", background=c["bg"])
        style.configure("Card.TFrame", background=c["surface"], relief="flat")
        style.configure("InnerCard.TFrame", background=c["surface2"], relief="flat")

        # Label
        style.configure("TLabel", background=c["bg"], foreground=c["text"], font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=c["surface"], foreground=c["text"], font=("Segoe UI", 10))
        style.configure("CardSub.TLabel", background=c["surface"], foreground=c["subtext"], font=("Segoe UI", 9))
        style.configure("Subtitle.TLabel", background=c["bg"], foreground=c["subtext"], font=("Segoe UI", 9))
        style.configure("CardHeader.TLabel", background=c["surface"], foreground=c["text"], font=("Segoe UI", 11, "bold"))
        style.configure("Title.TLabel", background=c["bg"], foreground=c["accent"], font=("Segoe UI", 16, "bold"))
        style.configure("Badge.TLabel", background=c["surface3"], foreground=c["accent"], font=("Consolas", 9, "bold"))
        style.configure("Success.TLabel", background=c["surface"], foreground=c["success"], font=("Segoe UI", 10, "bold"))
        style.configure("Warning.TLabel", background=c["surface"], foreground=c["warning"], font=("Segoe UI", 10, "bold"))
        style.configure("Error.TLabel", background=c["surface"], foreground=c["error"], font=("Segoe UI", 10, "bold"))

        # Notebook (Tabs)
        style.configure("TNotebook", background=c["bg"], borderwidth=0)
        style.configure("TNotebook.Tab",
            background=c["surface"],
            foreground=c["subtext"],
            padding=[16, 8],
            font=("Segoe UI", 10, "bold"),
            borderwidth=0
        )
        style.map("TNotebook.Tab",
            background=[("selected", c["surface3"]), ("active", c["surface2"])],
            foreground=[("selected", c["accent"]), ("active", c["text"])]
        )

        # Buttons
        style.configure("TButton",
            background=c["surface3"],
            foreground=c["text"],
            borderwidth=0,
            padding=[12, 6],
            font=("Segoe UI", 9, "bold")
        )
        style.map("TButton",
            background=[("active", c["accent"]), ("pressed", c["accent_hover"])],
            foreground=[("active", c["input_bg"]), ("pressed", c["input_bg"])]
        )

        style.configure("Primary.TButton",
            background=c["accent"],
            foreground=c["input_bg"],
            borderwidth=0,
            padding=[16, 8],
            font=("Segoe UI", 10, "bold")
        )
        style.map("Primary.TButton",
            background=[("active", c["accent_hover"]), ("pressed", "#ffffff")],
            foreground=[("active", c["input_bg"]), ("pressed", c["input_bg"])]
        )

        style.configure("Success.TButton",
            background=c["success"],
            foreground=c["input_bg"],
            borderwidth=0,
            padding=[16, 8],
            font=("Segoe UI", 10, "bold")
        )
        style.map("Success.TButton",
            background=[("active", "#c5f0be"), ("pressed", "#ffffff")],
            foreground=[("active", c["input_bg"]), ("pressed", c["input_bg"])]
        )

        style.configure("Warning.TButton",
            background=c["warning"],
            foreground=c["input_bg"],
            borderwidth=0,
            padding=[16, 8],
            font=("Segoe UI", 10, "bold")
        )
        style.map("Warning.TButton",
            background=[("active", "#fae8be"), ("pressed", "#ffffff")],
            foreground=[("active", c["input_bg"]), ("pressed", c["input_bg"])]
        )

        # Progressbar
        style.configure("TProgressbar",
            background=c["accent"],
            troughcolor=c["input_bg"],
            bordercolor=c["border"],
            borderwidth=0,
            thickness=10
        )

        # Entry & Spinbox
        style.configure("TEntry",
            fieldbackground=c["input_bg"],
            foreground=c["text"],
            insertcolor=c["text"],
            bordercolor=c["border"],
            lightcolor=c["border"],
            darkcolor=c["border"]
        )

        style.configure("TCheckbutton",
            background=c["surface"],
            foreground=c["text"],
            font=("Segoe UI", 9)
        )
        style.map("TCheckbutton",
            background=[("active", c["surface"])],
            foreground=[("active", c["accent"])]
        )

        style.configure("Horizontal.TScale",
            background=c["surface"],
            troughcolor=c["input_bg"],
            sliderrelief="flat"
        )

    def _build_ui(self):
        # Header banner
        header = tk.Frame(self, bg=self.colors["bg"], pady=10, padx=16)
        header.pack(fill="x")

        title_box = tk.Frame(header, bg=self.colors["bg"])
        title_box.pack(side="left")

        title_lbl = ttk.Label(title_box, text="VFC Studio — Video Frame Cipher", style="Title.TLabel")
        title_lbl.pack(anchor="w")

        sub_lbl = ttk.Label(
            title_box,
            text="Encrypt · authenticate · hide in PCM audio · recover with the same frame context",
            style="Subtitle.TLabel"
        )
        sub_lbl.pack(anchor="w")

        v_badge = tk.Label(
            header,
            text="v0.2 Spec",
            bg=self.colors["surface3"],
            fg=self.colors["accent"],
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
            relief="flat"
        )
        v_badge.pack(side="right", anchor="center")

        # Main notebook (Tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(4, 8))

        # 1. Encrypt Tab
        self.tab_encrypt = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.tab_encrypt, text="  🔒 Encrypt & Hide  ")
        self._build_encrypt_tab(self.tab_encrypt)

        # 2. Decrypt Tab
        self.tab_decrypt = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.tab_decrypt, text="  🔓 Extract & Decrypt  ")
        self._build_decrypt_tab(self.tab_decrypt)

        # 3. Carrier Tools Tab
        self.tab_tools = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.tab_tools, text="  🛠️ Carrier Prep & Tools  ")
        self._build_tools_tab(self.tab_tools)

        # 4. Specifications / Info Tab
        self.tab_info = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.tab_info, text="  ℹ️ Academy & Spec  ")
        self._build_info_tab(self.tab_info)

        # Activity Log Console at bottom
        self._build_log_console()

    # =========================================================================
    # TAB 1: ENCRYPT
    # =========================================================================
    def _build_encrypt_tab(self, parent):
        scroll_canvas = tk.Canvas(parent, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=scroll_canvas.yview)
        container = ttk.Frame(scroll_canvas, style="TFrame")

        container.bind(
            "<Configure>",
            lambda e: scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))
        )
        scroll_window = scroll_canvas.create_window((0, 0), window=container, anchor="nw")

        def _on_canvas_configure(event):
            scroll_canvas.itemconfig(scroll_window, width=event.width)
        scroll_canvas.bind("<Configure>", _on_canvas_configure)
        scroll_canvas.configure(yscrollcommand=scrollbar.set)

        scroll_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Card 1: Input Carrier Video
        card_carrier = self._create_card(container, "1. Carrier Video (Hiding Location)")
        
        row1 = ttk.Frame(card_carrier, style="Card.TFrame")
        row1.pack(fill="x", pady=4)
        
        self.enc_carrier_var = tk.StringVar()
        self.enc_carrier_var.trace_add("write", self._on_enc_carrier_changed)
        carrier_entry = tk.Entry(
            row1,
            textvariable=self.enc_carrier_var,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 9)
        )
        carrier_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        
        btn_browse_carrier = ttk.Button(row1, text="Browse Video...", command=self._browse_enc_carrier)
        btn_browse_carrier.pack(side="right")

        self.enc_carrier_info_lbl = ttk.Label(
            card_carrier,
            text="Please select a video file (.mkv recommended with PCM audio).",
            style="CardSub.TLabel"
        )
        self.enc_carrier_info_lbl.pack(anchor="w", pady=(2, 0))

        # Card 2: Secret File to Hide
        card_secret = self._create_card(container, "2. Secret File to Hide")
        
        row2 = ttk.Frame(card_secret, style="Card.TFrame")
        row2.pack(fill="x", pady=4)
        
        self.enc_secret_var = tk.StringVar()
        self.enc_secret_var.trace_add("write", self._on_enc_secret_changed)
        secret_entry = tk.Entry(
            row2,
            textvariable=self.enc_secret_var,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 9)
        )
        secret_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        
        btn_browse_secret = ttk.Button(row2, text="Browse File...", command=self._browse_enc_secret)
        btn_browse_secret.pack(side="right")

        self.enc_secret_info_lbl = ttk.Label(
            card_secret,
            text="Any file format supported (PDF, TXT, PNG, ZIP, DOCX, etc.)",
            style="CardSub.TLabel"
        )
        self.enc_secret_info_lbl.pack(anchor="w", pady=(2, 0))

        # Card 3: Key Derivation (Password + Frame Selector & Live Preview)
        card_keys = self._create_card(container, "3. Key Derivation (Password + Frame Binding)")

        # Password row
        pw_frame = ttk.Frame(card_keys, style="Card.TFrame")
        pw_frame.pack(fill="x", pady=(2, 8))

        ttk.Label(pw_frame, text="Encryption Password:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        
        self.enc_pw_var = tk.StringVar()
        self.enc_pw_entry = tk.Entry(
            pw_frame,
            textvariable=self.enc_pw_var,
            show="•",
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 10)
        )
        self.enc_pw_entry.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 8))

        self.enc_show_pw = tk.BooleanVar(value=False)
        btn_toggle_pw = ttk.Button(
            pw_frame,
            text="👁 Show",
            width=8,
            command=lambda: self._toggle_show_pw(self.enc_pw_entry, self.enc_show_pw, btn_toggle_pw)
        )
        btn_toggle_pw.pack(side="right")

        # Frame selection row + Live Preview Grid
        frame_grid = ttk.Frame(card_keys, style="Card.TFrame")
        frame_grid.pack(fill="x", pady=4)

        # Left column: frame slider & inputs
        f_left = ttk.Frame(frame_grid, style="Card.TFrame")
        f_left.pack(side="left", fill="both", expand=True, padx=(0, 16))

        f_control_row = ttk.Frame(f_left, style="Card.TFrame")
        f_control_row.pack(fill="x", pady=(0, 4))

        ttk.Label(f_control_row, text="Binding Frame #:", style="Card.TLabel").pack(side="left", padx=(0, 6))

        self.enc_frame_var = tk.IntVar(value=30)
        self.enc_frame_spin = tk.Spinbox(
            f_control_row,
            from_=0,
            to=999999,
            textvariable=self.enc_frame_var,
            width=8,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            command=self._on_enc_frame_spin_changed
        )
        self.enc_frame_spin.pack(side="left", padx=(0, 8))
        self.enc_frame_spin.bind("<Return>", lambda e: self._on_enc_frame_spin_changed())
        self.enc_frame_spin.bind("<FocusOut>", lambda e: self._on_enc_frame_spin_changed())

        btn_rand_frame = ttk.Button(f_control_row, text="🎲 Random", width=9, command=self._on_enc_rand_frame)
        btn_rand_frame.pack(side="left")

        self.enc_total_frames_lbl = ttk.Label(f_control_row, text="/ 0 frames", style="CardSub.TLabel")
        self.enc_total_frames_lbl.pack(side="left", padx=8)

        # Slider
        self.enc_slider = ttk.Scale(
            f_left,
            from_=0,
            to=100,
            orient="horizontal",
            style="Horizontal.TScale",
            command=self._on_enc_slider_moved
        )
        self.enc_slider.pack(fill="x", pady=8)

        # Fingerprint display
        self.enc_fp_lbl = tk.Label(
            f_left,
            text="Fingerprint: (Load video to inspect)",
            bg=self.colors["surface2"],
            fg=self.colors["accent"],
            font=("Consolas", 9),
            anchor="w",
            padx=8,
            pady=4,
            relief="flat"
        )
        self.enc_fp_lbl.pack(fill="x", pady=(4, 0))

        # Right column: Live Frame Preview Thumbnail Canvas
        f_right = ttk.Frame(frame_grid, style="Card.TFrame")
        f_right.pack(side="right")

        self.enc_preview_canvas = tk.Canvas(
            f_right,
            width=200,
            height=112,
            bg=self.colors["input_bg"],
            highlightthickness=1,
            highlightbackground=self.colors["surface2"]
        )
        self.enc_preview_canvas.pack()
        self.enc_preview_canvas.create_text(
            100, 56,
            text="Frame Preview\n(200x112)",
            fill=self.colors["subtext"],
            font=("Segoe UI", 8),
            justify="center"
        )

        # Card 4: Output Stego Video & Options (including Force Embed Demo Toggle)
        card_out = self._create_card(container, "4. Output Stego Video & Guardrail Controls")

        row_out = ttk.Frame(card_out, style="Card.TFrame")
        row_out.pack(fill="x", pady=4)

        self.enc_out_var = tk.StringVar()
        out_entry = tk.Entry(
            row_out,
            textvariable=self.enc_out_var,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 9)
        )
        out_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))

        btn_browse_out = ttk.Button(row_out, text="Save As...", command=self._browse_enc_out)
        btn_browse_out.pack(side="right")

        # Compression option
        opts_row = ttk.Frame(card_out, style="Card.TFrame")
        opts_row.pack(fill="x", pady=(6, 2))

        self.enc_compress_var = tk.BooleanVar(value=True)
        chk_compress = ttk.Checkbutton(
            opts_row,
            text="Enable zlib compression (reduces payload footprint before encryption)",
            variable=self.enc_compress_var,
            style="TCheckbutton"
        )
        chk_compress.pack(side="left")

        # Force embed / Guardrail Skip option
        opts_row2 = ttk.Frame(card_out, style="Card.TFrame")
        opts_row2.pack(fill="x", pady=(4, 0))

        self.enc_force_var = tk.BooleanVar(value=False)
        self.chk_force = ttk.Checkbutton(
            opts_row2,
            text="⚠️ Skip audio capacity guard (Force Embed / Demonstration mode)",
            variable=self.enc_force_var,
            style="TCheckbutton"
        )
        self.chk_force.pack(side="left")

        self.enc_force_hint = ttk.Label(
            card_out,
            text="Note: Force embedding a large file into a small audio carrier will truncate the ciphertext & HMAC tag, demonstrating corrupted decryption.",
            style="CardSub.TLabel"
        )
        self.enc_force_hint.pack(anchor="w", pady=(2, 0))

        # Real-time Progress & Status Bar Container
        self.enc_prog_container = ttk.Frame(container, style="Card.TFrame", padding=[12, 10])

        p_hdr = ttk.Frame(self.enc_prog_container, style="Card.TFrame")
        p_hdr.pack(fill="x", pady=(0, 4))

        self.enc_prog_lbl = ttk.Label(
            p_hdr,
            text="Ready",
            font=("Segoe UI", 9, "bold"),
            style="Card.TLabel"
        )
        self.enc_prog_lbl.pack(side="left")

        self.enc_prog_pct = tk.Label(
            p_hdr,
            text="0%",
            bg=self.colors["surface3"],
            fg=self.colors["accent"],
            font=("Consolas", 9, "bold"),
            padx=6,
            pady=2
        )
        self.enc_prog_pct.pack(side="right")

        self.enc_progressbar = ttk.Progressbar(
            self.enc_prog_container,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            style="TProgressbar"
        )
        self.enc_progressbar.pack(fill="x", pady=(4, 0))

        # Action Box: Progress & Encrypt Buttons
        action_card = ttk.Frame(container, style="TFrame")
        action_card.pack(fill="x", pady=(12, 16))

        btn_box = ttk.Frame(action_card, style="TFrame")
        btn_box.pack(fill="x")

        self.btn_encrypt = ttk.Button(
            btn_box,
            text="🔒  Encrypt & Embed Secret",
            style="Primary.TButton",
            command=self._start_encrypt
        )
        self.btn_encrypt.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 6))

        self.btn_force_embed = ttk.Button(
            btn_box,
            text="⚠️  Force Embed (Demo Truncation)",
            style="Warning.TButton",
            command=lambda: self._start_encrypt(force_override=True)
        )
        self.btn_force_embed.pack(side="right", ipady=4)

    # =========================================================================
    # TAB 2: DECRYPT
    # =========================================================================
    def _build_decrypt_tab(self, parent):
        scroll_canvas = tk.Canvas(parent, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=scroll_canvas.yview)
        container = ttk.Frame(scroll_canvas, style="TFrame")

        container.bind(
            "<Configure>",
            lambda e: scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))
        )
        scroll_window = scroll_canvas.create_window((0, 0), window=container, anchor="nw")

        def _on_canvas_configure(event):
            scroll_canvas.itemconfig(scroll_window, width=event.width)
        scroll_canvas.bind("<Configure>", _on_canvas_configure)
        scroll_canvas.configure(yscrollcommand=scrollbar.set)

        scroll_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Card 1: Stego Video Input
        card_stego = self._create_card(container, "1. Stego Video (Containing Hidden Secret)")
        
        row1 = ttk.Frame(card_stego, style="Card.TFrame")
        row1.pack(fill="x", pady=4)
        
        self.dec_stego_var = tk.StringVar()
        self.dec_stego_var.trace_add("write", self._on_dec_stego_changed)
        stego_entry = tk.Entry(
            row1,
            textvariable=self.dec_stego_var,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 9)
        )
        stego_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        
        btn_browse_stego = ttk.Button(row1, text="Browse Stego Video...", command=self._browse_dec_stego)
        btn_browse_stego.pack(side="right")

        self.dec_stego_info_lbl = ttk.Label(
            card_stego,
            text="Select the carrier video containing the hidden payload.",
            style="CardSub.TLabel"
        )
        self.dec_stego_info_lbl.pack(anchor="w", pady=(2, 0))

        # Card 2: Key Credentials (Password & Frame)
        card_keys = self._create_card(container, "2. Key Credentials (Password & Frame Number)")

        pw_frame = ttk.Frame(card_keys, style="Card.TFrame")
        pw_frame.pack(fill="x", pady=(2, 8))

        ttk.Label(pw_frame, text="Decryption Password:", style="Card.TLabel").pack(side="left", padx=(0, 8))
        
        self.dec_pw_var = tk.StringVar()
        self.dec_pw_entry = tk.Entry(
            pw_frame,
            textvariable=self.dec_pw_var,
            show="•",
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 10)
        )
        self.dec_pw_entry.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 8))

        self.dec_show_pw = tk.BooleanVar(value=False)
        btn_toggle_pw = ttk.Button(
            pw_frame,
            text="👁 Show",
            width=8,
            command=lambda: self._toggle_show_pw(self.dec_pw_entry, self.dec_show_pw, btn_toggle_pw)
        )
        btn_toggle_pw.pack(side="right")

        # Frame selection row + Live Preview Grid
        frame_grid = ttk.Frame(card_keys, style="Card.TFrame")
        frame_grid.pack(fill="x", pady=4)

        # Left column
        f_left = ttk.Frame(frame_grid, style="Card.TFrame")
        f_left.pack(side="left", fill="both", expand=True, padx=(0, 16))

        f_control_row = ttk.Frame(f_left, style="Card.TFrame")
        f_control_row.pack(fill="x", pady=(0, 4))

        ttk.Label(f_control_row, text="Exact Frame #:", style="Card.TLabel").pack(side="left", padx=(0, 6))

        self.dec_frame_var = tk.IntVar(value=30)
        self.dec_frame_spin = tk.Spinbox(
            f_control_row,
            from_=0,
            to=999999,
            textvariable=self.dec_frame_var,
            width=8,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            command=self._on_dec_frame_spin_changed
        )
        self.dec_frame_spin.pack(side="left", padx=(0, 8))
        self.dec_frame_spin.bind("<Return>", lambda e: self._on_dec_frame_spin_changed())
        self.dec_frame_spin.bind("<FocusOut>", lambda e: self._on_dec_frame_spin_changed())

        self.dec_total_frames_lbl = ttk.Label(f_control_row, text="/ 0 frames", style="CardSub.TLabel")
        self.dec_total_frames_lbl.pack(side="left", padx=8)

        # Slider
        self.dec_slider = ttk.Scale(
            f_left,
            from_=0,
            to=100,
            orient="horizontal",
            style="Horizontal.TScale",
            command=self._on_dec_slider_moved
        )
        self.dec_slider.pack(fill="x", pady=8)

        # Fingerprint display
        self.dec_fp_lbl = tk.Label(
            f_left,
            text="Fingerprint: (Load video to inspect)",
            bg=self.colors["surface2"],
            fg=self.colors["accent"],
            font=("Consolas", 9),
            anchor="w",
            padx=8,
            pady=4,
            relief="flat"
        )
        self.dec_fp_lbl.pack(fill="x", pady=(4, 0))

        # Right column: Frame Preview Canvas
        f_right = ttk.Frame(frame_grid, style="Card.TFrame")
        f_right.pack(side="right")

        self.dec_preview_canvas = tk.Canvas(
            f_right,
            width=200,
            height=112,
            bg=self.colors["input_bg"],
            highlightthickness=1,
            highlightbackground=self.colors["surface2"]
        )
        self.dec_preview_canvas.pack()
        self.dec_preview_canvas.create_text(
            100, 56,
            text="Frame Preview\n(200x112)",
            fill=self.colors["subtext"],
            font=("Segoe UI", 8),
            justify="center"
        )

        # Card 3: Output Destination Folder
        card_dest = self._create_card(container, "3. Output Destination Folder")

        row_dest = ttk.Frame(card_dest, style="Card.TFrame")
        row_dest.pack(fill="x", pady=4)

        default_out_dir = os.path.join(PROJECT_ROOT, "decrypted")
        self.dec_out_dir_var = tk.StringVar(value=default_out_dir)
        dest_entry = tk.Entry(
            row_dest,
            textvariable=self.dec_out_dir_var,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 9)
        )
        dest_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))

        btn_browse_dest = ttk.Button(row_dest, text="Browse Folder...", command=self._browse_dec_out_dir)
        btn_browse_dest.pack(side="right")

        ttk.Label(
            card_dest,
            text="The original filename embedded inside the encrypted payload will be automatically restored.",
            style="CardSub.TLabel"
        ).pack(anchor="w", pady=(2, 0))

        # Decrypt Progress Container
        self.dec_prog_container = ttk.Frame(container, style="Card.TFrame", padding=[12, 10])

        dp_hdr = ttk.Frame(self.dec_prog_container, style="Card.TFrame")
        dp_hdr.pack(fill="x", pady=(0, 4))

        self.dec_prog_lbl = ttk.Label(
            dp_hdr,
            text="Ready",
            font=("Segoe UI", 9, "bold"),
            style="Card.TLabel"
        )
        self.dec_prog_lbl.pack(side="left")

        self.dec_prog_pct = tk.Label(
            dp_hdr,
            text="0%",
            bg=self.colors["surface3"],
            fg=self.colors["success"],
            font=("Consolas", 9, "bold"),
            padx=6,
            pady=2
        )
        self.dec_prog_pct.pack(side="right")

        self.dec_progressbar = ttk.Progressbar(
            self.dec_prog_container,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            style="TProgressbar"
        )
        self.dec_progressbar.pack(fill="x", pady=(4, 0))

        # Action Box: Decrypt Button
        action_card = ttk.Frame(container, style="TFrame")
        action_card.pack(fill="x", pady=(12, 16))

        self.btn_decrypt = ttk.Button(
            action_card,
            text="🔓  Extract & Decrypt Secret",
            style="Success.TButton",
            command=self._start_decrypt
        )
        self.btn_decrypt.pack(fill="x", ipady=4)

    # =========================================================================
    # TAB 3: TOOLS & CARRIER PREP
    # =========================================================================
    def _build_tools_tab(self, parent):
        scroll_canvas = tk.Canvas(parent, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=scroll_canvas.yview)
        container = ttk.Frame(scroll_canvas, style="TFrame")

        container.bind(
            "<Configure>",
            lambda e: scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))
        )
        scroll_window = scroll_canvas.create_window((0, 0), window=container, anchor="nw")

        def _on_canvas_configure(event):
            scroll_canvas.itemconfig(scroll_window, width=event.width)
        scroll_canvas.bind("<Configure>", _on_canvas_configure)
        scroll_canvas.configure(yscrollcommand=scrollbar.set)

        scroll_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Tool 1: Automatic Carrier Video Converter
        card_conv = self._create_card(container, "Video to VFC Carrier Converter (MP4/MOV -> MKV + PCM)")

        ttk.Label(
            card_conv,
            text="VFC requires lossless PCM audio in a container like MKV. Convert any normal MP4 or MOV video here.",
            style="CardSub.TLabel"
        ).pack(anchor="w", pady=(0, 8))

        row_conv_in = ttk.Frame(card_conv, style="Card.TFrame")
        row_conv_in.pack(fill="x", pady=4)

        self.tool_conv_in_var = tk.StringVar()
        self.tool_conv_in_var.trace_add("write", self._on_tool_conv_in_changed)
        entry_cin = tk.Entry(
            row_conv_in,
            textvariable=self.tool_conv_in_var,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 9)
        )
        entry_cin.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))

        btn_browse_cin = ttk.Button(row_conv_in, text="Select Video...", command=self._browse_tool_conv_in)
        btn_browse_cin.pack(side="right")

        row_conv_out = ttk.Frame(card_conv, style="Card.TFrame")
        row_conv_out.pack(fill="x", pady=4)

        self.tool_conv_out_var = tk.StringVar()
        entry_cout = tk.Entry(
            row_conv_out,
            textvariable=self.tool_conv_out_var,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 9)
        )
        entry_cout.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))

        btn_browse_cout = ttk.Button(row_conv_out, text="Output MKV...", command=self._browse_tool_conv_out)
        btn_browse_cout.pack(side="right")

        self.btn_convert_carrier = ttk.Button(
            card_conv,
            text="⚙️ Convert to Lossless Carrier (ffmpeg)",
            style="Primary.TButton",
            command=self._start_convert_carrier
        )
        self.btn_convert_carrier.pack(fill="x", pady=(8, 2))

        # Tool 2: Carrier Capacity & Audio Inspector
        card_insp = self._create_card(container, "Carrier Audio Capacity & Integrity Inspector")

        ttk.Label(
            card_insp,
            text="Inspect how many bytes can be hidden in an audio track without perceptual distortion.",
            style="CardSub.TLabel"
        ).pack(anchor="w", pady=(0, 8))

        row_insp = ttk.Frame(card_insp, style="Card.TFrame")
        row_insp.pack(fill="x", pady=4)

        self.tool_insp_var = tk.StringVar()
        entry_insp = tk.Entry(
            row_insp,
            textvariable=self.tool_insp_var,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Segoe UI", 9)
        )
        entry_insp.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))

        btn_browse_insp = ttk.Button(row_insp, text="Inspect Video...", command=self._browse_tool_insp)
        btn_browse_insp.pack(side="right")

        self.insp_results_box = tk.Text(
            card_insp,
            height=6,
            bg=self.colors["input_bg"],
            fg=self.colors["text"],
            relief="flat",
            font=("Consolas", 9),
            padx=8,
            pady=8
        )
        self.insp_results_box.pack(fill="x", pady=(8, 0))
        self.insp_results_box.insert("1.0", "Select a carrier video above to inspect its audio steganography capacity.")
        self.insp_results_box.configure(state="disabled")

    # =========================================================================
    # TAB 4: SPECIFICATION & ABOUT
    # =========================================================================
    def _build_info_tab(self, parent):
        scroll_canvas = tk.Canvas(parent, bg=self.colors["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=scroll_canvas.yview)
        container = ttk.Frame(scroll_canvas, style="TFrame")

        container.bind(
            "<Configure>",
            lambda e: scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))
        )
        scroll_window = scroll_canvas.create_window((0, 0), window=container, anchor="nw")

        def _on_canvas_configure(event):
            scroll_canvas.itemconfig(scroll_window, width=event.width)
        scroll_canvas.bind("<Configure>", _on_canvas_configure)
        scroll_canvas.configure(yscrollcommand=scrollbar.set)

        scroll_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        card_about = self._create_card(container, "About VFC — Video Frame Cipher (v0.2)")

        about_text = (
            "VFC is an educational cryptographic-steganography system designed for coursework and demonstration. "
            "The password is the secret; the frame fingerprint is public context that binds the operation to a carrier and frame.\n\n"
            "THREE SEPARATED KEYS\n"
            "  K_embed  — selects deterministic audio positions and derives the keyed magic marker.\n"
            "  K_enc    — supplies the seven 16-byte keys RK0..RK6 used by the block cipher.\n"
            "  K_auth   — computes HMAC-SHA256 over the header and ciphertext.\n\n"
            "IMPLEMENTED PIPELINE\n"
            "  • Frame Fingerprint: Extracts a 64-bit perceptual hash (aHash) from a chosen grayscale video frame.\n"
            "  • Key Derivation: PBKDF2-HMAC-SHA256 with separate domain labels; only K_enc and K_auth include the random salt.\n"
            "  • SPN Block Cipher: 128-bit custom cipher with initial RK0 whitening followed by 6 rounds of SubBytes, ShiftRows, MixColumns, and AddRoundKey.\n"
            "  • Inner Package: Stores filename, original size, compression flag, and file bytes before PKCS#7 padding.\n"
            "  • CBC Mode + PKCS#7: For each padded block, CBC XORs with the IV/previous ciphertext and calls the SPN primitive.\n"
            "  • Authenticated Payload: Encrypt-then-MAC with HMAC-SHA256 and key-derived magic header to prevent password-oracle leakage.\n"
            "  • Steganography: LSB replacement in 16-bit PCM samples satisfying |sample >> 1| >= 2, with CSPRNG Fisher-Yates positions.\n"
            "  • Capacity Guard: Normal operation refuses oversized payloads. Force mode is only a classroom demonstration of authenticated truncation failure.\n\n"
            "Notice: Educational software for academic cryptographic study. Not for production secrecy."
        )

        txt = tk.Text(
            card_about,
            height=21,
            bg=self.colors["surface2"],
            fg=self.colors["text"],
            relief="flat",
            wrap="word",
            font=("Segoe UI", 9),
            padx=12,
            pady=12
        )
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", about_text)
        txt.configure(state="disabled")

        card_teach = self._create_card(container, "Presentation tools")
        ttk.Label(
            card_teach,
            text=(
                "Use the block tracer for byte-by-byte SPN arithmetic. Use the Arabic Academic Kit for the full "
                "fingerprint → keys → inner package → CBC calling SPN → payload/HMAC → audio explanation backed by the generated teaching vector."
            ),
            style="CardSub.TLabel",
            wraplength=820,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        launch_row = ttk.Frame(card_teach, style="Card.TFrame")
        launch_row.pack(fill="x")
        ttk.Button(
            launch_row,
            text="Open Block Cipher Tracer",
            style="Primary.TButton",
            command=self._launch_trace_gui,
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(
            launch_row,
            text="Open Arabic Academic Kit",
            command=self._launch_academic_kit,
        ).pack(side="left", fill="x", expand=True, padx=(6, 0))

    # =========================================================================
    # CONSOLE & LOGGING
    # =========================================================================
    def _build_log_console(self):
        console_frame = tk.Frame(self, bg=self.colors["surface"], padx=12, pady=8)
        console_frame.pack(fill="x", side="bottom", padx=16, pady=(0, 12))

        c_header = tk.Frame(console_frame, bg=self.colors["surface"])
        c_header.pack(fill="x", pady=(0, 4))

        ttk.Label(c_header, text="Activity & Status Log", style="CardHeader.TLabel").pack(side="left")

        btn_clear = ttk.Button(c_header, text="Clear Log", width=9, command=self._clear_log)
        btn_clear.pack(side="right")

        self.log_text = tk.Text(
            console_frame,
            height=4,
            bg=self.colors["input_bg"],
            fg=self.colors["subtext"],
            insertbackground=self.colors["text"],
            relief="flat",
            font=("Consolas", 9),
            padx=8,
            pady=4
        )
        self.log_text.pack(fill="x")
        self.log_text.tag_config("info", foreground=self.colors["subtext"])
        self.log_text.tag_config("success", foreground=self.colors["success"])
        self.log_text.tag_config("warning", foreground=self.colors["warning"])
        self.log_text.tag_config("error", foreground=self.colors["error"])
        self.log_text.tag_config("highlight", foreground=self.colors["accent"])

        self.log("VFC Studio v0.2 initialized. Ready.", "highlight")

    def log(self, message: str, level: str = "info"):
        """Thread-safe logging to the bottom console."""
        def _do_log():
            timestamp = time.strftime("%H:%M:%S")
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"[{timestamp}] {message}\n", level)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        if threading.current_thread() is threading.main_thread():
            _do_log()
        else:
            self.after(0, _do_log)

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _launch_trace_gui(self):
        """Launch the standalone SPN tracer with the same Python interpreter."""
        tracer = os.path.join(PROJECT_ROOT, "trace_gui.py")
        if not os.path.isfile(tracer):
            messagebox.showerror("Tracer not found", f"Could not find:\n{tracer}")
            return
        try:
            subprocess.Popen([sys.executable, tracer], cwd=PROJECT_ROOT)
            self.log("Opened the block-cipher teaching tracer.", "success")
        except Exception as ex:
            messagebox.showerror("Could not open tracer", str(ex))

    def _launch_academic_kit(self):
        """Start the existing Vite dev server on demand and open the Arabic kit."""
        kit_dir = os.path.join(PROJECT_ROOT, "academic-kit")
        package_file = os.path.join(kit_dir, "package.json")
        node_modules = os.path.join(kit_dir, "node_modules")
        if not os.path.isfile(package_file) or not os.path.isdir(node_modules):
            messagebox.showinfo(
                "Academic Kit setup",
                "The Academic Kit is present, but its existing dependencies are not installed.\n\n"
                "From academic-kit, run the documented npm install command, then try again.",
            )
            return

        try:
            if self._academic_process is None or self._academic_process.poll() is not None:
                vite_name = "vite.cmd" if sys.platform == "win32" else "vite"
                vite_command = os.path.join(node_modules, ".bin", vite_name)
                if not os.path.isfile(vite_command):
                    raise FileNotFoundError("The existing local Vite executable was not found.")
                self._academic_process = subprocess.Popen(
                    [vite_command, "--host", "127.0.0.1", "--port", "5173"],
                    cwd=kit_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            self.after(1200, lambda: webbrowser.open("http://127.0.0.1:5173/?guide=1#lab"))
            self.log("Opening the Arabic Academic Kit at http://127.0.0.1:5173", "success")
        except Exception as ex:
            messagebox.showerror("Could not open Academic Kit", str(ex))

    # =========================================================================
    # HELPERS & UI BUILDERS
    # =========================================================================
    def _create_card(self, parent, title: str):
        card = ttk.Frame(parent, style="Card.TFrame", padding=[14, 12])
        card.pack(fill="x", pady=6)
        
        lbl_title = ttk.Label(card, text=title, style="CardHeader.TLabel")
        lbl_title.pack(anchor="w", pady=(0, 6))
        return card

    def _toggle_show_pw(self, entry: tk.Entry, var: tk.BooleanVar, btn: ttk.Button):
        if var.get():
            entry.configure(show="•")
            btn.configure(text="👁 Show")
            var.set(False)
        else:
            entry.configure(show="")
            btn.configure(text="🔒 Hide")
            var.set(True)

    # =========================================================================
    # VIDEO METADATA & LIVE PREVIEW SYSTEM
    # =========================================================================
    def _load_video_metadata(self, path: str):
        if not path or not os.path.isfile(path):
            return None
        try:
            cap = cv2.VideoCapture(path)
            if not cap.isOpened():
                return None
            frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = float(cap.get(cv2.CAP_PROP_FPS) or 25.0)
            w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            cap.release()
            return {"path": path, "frames": frames, "fps": fps, "w": w, "h": h}
        except Exception as ex:
            err_text = str(ex)
            self.log(f"Error reading video metadata: {err_text}", "error")
            return None

    def _fetch_frame_data(self, video_path: str, frame_no: int):
        cache_key = (video_path, frame_no)
        if cache_key in self._preview_cache:
            return self._preview_cache[cache_key]

        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                return None, ""
            cap.set(cv2.CAP_PROP_POS_FRAMES, frame_no)
            ok, frame = cap.read()
            cap.release()
            if not ok or frame is None:
                return None, ""

            # 1) Calculate exact 64-bit fingerprint
            gray_full = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            fp_bytes = fingerprint_from_gray(gray_full.tolist())
            fp_hex = fp_bytes.hex()

            # 2) Create 200x112 thumbnail for Tkinter canvas
            thumb = cv2.resize(frame, (200, 112))
            _, buf = cv2.imencode('.ppm', thumb)
            photo = tk.PhotoImage(data=buf.tobytes())

            self._preview_cache[cache_key] = (photo, fp_hex)
            return photo, fp_hex
        except Exception as ex:
            err_text = str(ex)
            return None, f"Error: {err_text}"

    def _schedule_preview_update(self, is_encrypt: bool):
        if self._debounce_timer is not None:
            self.after_cancel(self._debounce_timer)
        self._debounce_timer = self.after(80, lambda: self._update_preview_worker(is_encrypt))

    def _update_preview_worker(self, is_encrypt: bool):
        if is_encrypt:
            path = self.enc_carrier_var.get().strip()
            frame_no = self.enc_frame_var.get()
            canvas = self.enc_preview_canvas
            fp_label = self.enc_fp_lbl
        else:
            path = self.dec_stego_var.get().strip()
            frame_no = self.dec_frame_var.get()
            canvas = self.dec_preview_canvas
            fp_label = self.dec_fp_lbl

        if not path or not os.path.isfile(path):
            canvas.delete("all")
            canvas.create_text(100, 56, text="No Video Loaded", fill=self.colors["subtext"], font=("Segoe UI", 9))
            fp_label.configure(text="Fingerprint: (Load video to inspect)")
            return

        def _worker():
            photo, fp_hex = self._fetch_frame_data(path, frame_no)

            def _update_ui():
                if photo:
                    canvas.delete("all")
                    canvas.image = photo  # prevent GC
                    canvas.create_image(0, 0, anchor="nw", image=photo)
                    fp_label.configure(text=f"Fingerprint: {fp_hex} (64-bit aHash)")
                else:
                    canvas.delete("all")
                    canvas.create_text(100, 56, text=f"Frame {frame_no} N/A", fill=self.colors["error"], font=("Segoe UI", 9))
                    fp_label.configure(text="Fingerprint: N/A")

            self.after(0, _update_ui)

        threading.Thread(target=_worker, daemon=True).start()

    # =========================================================================
    # ENCRYPT TAB EVENT HANDLERS
    # =========================================================================
    def _browse_enc_carrier(self):
        filename = filedialog.askopenfilename(
            title="Select Carrier Video",
            filetypes=[("Video Files", "*.mkv *.mp4 *.mov *.avi *.webm"), ("All Files", "*.*")]
        )
        if filename:
            self.enc_carrier_var.set(filename)

    def _on_enc_carrier_changed(self, *args):
        path = self.enc_carrier_var.get().strip()
        if not path or not os.path.isfile(path):
            self.enc_carrier_info_lbl.configure(text="Please select a video file.", style="CardSub.TLabel")
            self.enc_total_frames_lbl.configure(text="/ 0 frames")
            self._schedule_preview_update(is_encrypt=True)
            return

        meta = self._load_video_metadata(path)
        if meta and meta["frames"] > 0:
            self.enc_video_meta = meta
            frames = meta["frames"]
            duration_s = frames / meta["fps"] if meta["fps"] > 0 else 0
            size_mb = os.path.getsize(path) / (1024 * 1024)
            info_str = f"✓ {meta['w']}x{meta['h']} @ {meta['fps']:.1f}fps | {frames} frames ({duration_s:.1f}s) | {size_mb:.1f} MB"
            self.enc_carrier_info_lbl.configure(text=info_str, style="Success.TLabel")
            self.enc_total_frames_lbl.configure(text=f"/ {frames - 1} frames")

            # Update slider & spinbox bounds
            self.enc_slider.configure(to=max(0, frames - 1))
            self.enc_frame_spin.configure(to=max(0, frames - 1))

            # Auto suggest output path if empty
            if not self.enc_out_var.get():
                stem, _ = os.path.splitext(path)
                self.enc_out_var.set(f"{stem}_stego.mkv")

            self._schedule_preview_update(is_encrypt=True)
            self.log(f"Carrier loaded: {os.path.basename(path)} ({frames} frames)", "info")
        else:
            self.enc_carrier_info_lbl.configure(text="⚠️ Unable to read video stream.", style="Error.TLabel")

    def _browse_enc_secret(self):
        filename = filedialog.askopenfilename(
            title="Select Secret File to Hide",
            filetypes=[("All Files", "*.*")]
        )
        if filename:
            self.enc_secret_var.set(filename)

    def _on_enc_secret_changed(self, *args):
        path = self.enc_secret_var.get().strip()
        if path and os.path.isfile(path):
            size = os.path.getsize(path)
            self.enc_secret_info_lbl.configure(
                text=f"✓ File: {os.path.basename(path)} ({format_size(size)})",
                style="Success.TLabel"
            )
        else:
            self.enc_secret_info_lbl.configure(
                text="Any file format supported (PDF, TXT, PNG, ZIP, DOCX, etc.)",
                style="CardSub.TLabel"
            )

    def _browse_enc_out(self):
        filename = filedialog.asksaveasfilename(
            title="Save Stego Video As",
            defaultextension=".mkv",
            filetypes=[("Matroska Video (*.mkv)", "*.mkv"), ("All Files", "*.*")]
        )
        if filename:
            self.enc_out_var.set(filename)

    def _on_enc_slider_moved(self, val):
        frame = int(float(val))
        if self.enc_frame_var.get() != frame:
            self.enc_frame_var.set(frame)
            self._schedule_preview_update(is_encrypt=True)

    def _on_enc_frame_spin_changed(self):
        try:
            frame = int(self.enc_frame_var.get())
            self.enc_slider.set(frame)
            self._schedule_preview_update(is_encrypt=True)
        except Exception:
            pass

    def _on_enc_rand_frame(self):
        import random
        max_f = max(0, self.enc_video_meta.get("frames", 100) - 1)
        if max_f > 0:
            rand_f = random.randint(0, max_f)
            self.enc_frame_var.set(rand_f)
            self.enc_slider.set(rand_f)
            self._schedule_preview_update(is_encrypt=True)

    def _update_enc_progress_ui(self, fraction: float, message: str = ""):
        pct = int(min(1.0, max(0.0, fraction)) * 100)
        self.enc_progressbar.configure(value=pct)
        self.enc_prog_pct.configure(text=f"{pct}%")
        if message:
            self.enc_prog_lbl.configure(text=message)

    def _start_encrypt(self, force_override: bool = None):
        in_video = self.enc_carrier_var.get().strip()
        secret_file = self.enc_secret_var.get().strip()
        out_video = self.enc_out_var.get().strip()
        password_str = self.enc_pw_var.get()
        frame_no = self.enc_frame_var.get()
        compress = self.enc_compress_var.get()

        force = self.enc_force_var.get() if force_override is None else force_override

        # Validation
        if not in_video or not os.path.isfile(in_video):
            messagebox.showerror("Error", "Please select a valid carrier video file.")
            return
        if not secret_file or not os.path.isfile(secret_file):
            messagebox.showerror("Error", "Please select a valid secret file to hide.")
            return
        if not out_video:
            messagebox.showerror("Error", "Please specify an output stego video path.")
            return
        if not password_str:
            if not messagebox.askyesno("Warning", "Password is empty. Proceed with empty password?"):
                return

        # Disable UI and show determinate progress container
        self.btn_encrypt.configure(state="disabled")
        self.btn_force_embed.configure(state="disabled")
        self.enc_prog_container.pack(fill="x", pady=(0, 8), before=self.btn_encrypt.master)
        self._update_enc_progress_ui(0.01, "Initializing encryption pipeline...")

        mode_tag = " [FORCE EMBED DEMO]" if force else ""
        self.log(f"Starting encryption{mode_tag}: hiding '{os.path.basename(secret_file)}' into frame #{frame_no}...", "highlight")

        def _worker():
            try:
                pw_bytes = password_str.encode("utf-8")

                def _progress_cb(frac, msg=""):
                    self.after(0, lambda f=frac, m=msg: self._update_enc_progress_ui(f, m))

                stats = video.encrypt_video(
                    in_video,
                    secret_file,
                    out_video,
                    pw_bytes,
                    frame_no,
                    compress=compress,
                    force=force,
                    progress_cb=_progress_cb
                )

                def _on_success():
                    self._update_enc_progress_ui(1.0, "Complete!")
                    self.btn_encrypt.configure(state="normal")
                    self.btn_force_embed.configure(state="normal")

                    is_trunc = stats.get("truncated", False)
                    if is_trunc:
                        self.log(f"⚠️ FORCE EMBED COMPLETE: Truncated payload saved to: {out_video}", "warning")
                        self.log(f"  • Needed: {stats['needed_samples']:,} samples ({stats['capacity_pct']:.1f}% capacity)", "warning")
                        self.log(f"  • Embedded: {stats['used_samples']:,}/{stats['eligible_samples']:,} available samples (Remainder dropped)", "warning")
                        self.log("  • NOTE: Decryption will fail authentication because data was cut off.", "warning")

                        messagebox.showwarning(
                            "Force Embed Complete (Demonstration)",
                            f"Demonstration payload embedded into:\n{out_video}\n\n"
                            f"⚠️ CAPACITY WAS EXCEEDED:\n"
                            f"• Total Needed Bits: {stats['needed_samples']:,}\n"
                            f"• Carrier Available Samples: {stats['eligible_samples']:,}\n"
                            f"• Discarded / Lost Bits: {stats['needed_samples'] - stats['used_samples']:,}\n"
                            f"• Audio Capacity Ratio: {stats['capacity_pct']:.1f}%\n\n"
                            "What happened:\n"
                            "1. All available audio samples were modified with the start of the payload.\n"
                            "2. The remaining ciphertext and HMAC authentication tag were cut off.\n"
                            "3. If you try to Decrypt this video, it will fail authentication as expected."
                        )
                    else:
                        self.log(f"Encryption successful! Stego saved to: {out_video}", "success")
                        self.log(f"  • Payload: {stats['payload_bytes']} bytes ({stats['ciphertext_bytes']} bytes cipher)", "info")
                        self.log(f"  • Capacity: {stats['used_samples']}/{stats['eligible_samples']} samples ({stats['capacity_pct']:.2f}%)", "info")

                        res = messagebox.askyesno(
                            "Encryption Complete",
                            f"Secret file embedded successfully into:\n{out_video}\n\n"
                            f"• Payload Size: {format_size(stats['payload_bytes'])}\n"
                            f"• Audio Capacity Used: {stats['capacity_pct']:.2f}%\n"
                            f"• Frame #{frame_no} aHash: {stats['fingerprint'][:16]}...\n\n"
                            "Would you like to open the output folder now?"
                        )
                        if res:
                            open_in_file_manager(out_video)

                self.after(0, _on_success)
            except Exception as ex:
                err_msg = str(ex)
                def _on_error():
                    self.enc_prog_lbl.configure(text=f"Failed: {err_msg}")
                    self.btn_encrypt.configure(state="normal")
                    self.btn_force_embed.configure(state="normal")
                    self.log(f"Encryption failed: {err_msg}", "error")

                    # If failed because audio is too small, offer one-click force embed
                    if "audio too small" in err_msg:
                        ask_force = messagebox.askyesno(
                            "Audio Capacity Guardrail",
                            f"{err_msg}\n\n"
                            "The secret file is larger than the audio track can hold.\n\n"
                            "Would you like to FORCE EMBED anyway to demonstrate what happens when a large file is truncated in a small carrier?"
                        )
                        if ask_force:
                            self.enc_force_var.set(True)
                            self._start_encrypt(force_override=True)
                    else:
                        messagebox.showerror("Encryption Failed", f"An error occurred during encryption:\n\n{err_msg}")
                self.after(0, _on_error)

        threading.Thread(target=_worker, daemon=True).start()

    # =========================================================================
    # DECRYPT TAB EVENT HANDLERS
    # =========================================================================
    def _browse_dec_stego(self):
        filename = filedialog.askopenfilename(
            title="Select Stego Video",
            filetypes=[("Video Files", "*.mkv *.mp4 *.mov *.avi *.webm"), ("All Files", "*.*")]
        )
        if filename:
            self.dec_stego_var.set(filename)

    def _on_dec_stego_changed(self, *args):
        path = self.dec_stego_var.get().strip()
        if not path or not os.path.isfile(path):
            self.dec_stego_info_lbl.configure(text="Select the carrier video containing the hidden payload.", style="CardSub.TLabel")
            self.dec_total_frames_lbl.configure(text="/ 0 frames")
            self._schedule_preview_update(is_encrypt=False)
            return

        meta = self._load_video_metadata(path)
        if meta and meta["frames"] > 0:
            self.dec_video_meta = meta
            frames = meta["frames"]
            info_str = f"✓ {meta['w']}x{meta['h']} @ {meta['fps']:.1f}fps | {frames} frames"
            self.dec_stego_info_lbl.configure(text=info_str, style="Success.TLabel")
            self.dec_total_frames_lbl.configure(text=f"/ {frames - 1} frames")

            self.dec_slider.configure(to=max(0, frames - 1))
            self.dec_frame_spin.configure(to=max(0, frames - 1))

            self._schedule_preview_update(is_encrypt=False)
            self.log(f"Stego video loaded: {os.path.basename(path)}", "info")
        else:
            self.dec_stego_info_lbl.configure(text="⚠️ Unable to read video stream.", style="Error.TLabel")

    def _on_dec_slider_moved(self, val):
        frame = int(float(val))
        if self.dec_frame_var.get() != frame:
            self.dec_frame_var.set(frame)
            self._schedule_preview_update(is_encrypt=False)

    def _on_dec_frame_spin_changed(self):
        try:
            frame = int(self.dec_frame_var.get())
            self.dec_slider.set(frame)
            self._schedule_preview_update(is_encrypt=False)
        except Exception:
            pass

    def _browse_dec_out_dir(self):
        dirname = filedialog.askdirectory(title="Select Destination Output Folder")
        if dirname:
            self.dec_out_dir_var.set(dirname)

    def _update_dec_progress_ui(self, fraction: float, message: str = ""):
        pct = int(min(1.0, max(0.0, fraction)) * 100)
        self.dec_progressbar.configure(value=pct)
        self.dec_prog_pct.configure(text=f"{pct}%")
        if message:
            self.dec_prog_lbl.configure(text=message)

    def _start_decrypt(self):
        stego_video = self.dec_stego_var.get().strip()
        out_dir = self.dec_out_dir_var.get().strip()
        password_str = self.dec_pw_var.get()
        frame_no = self.dec_frame_var.get()

        if not stego_video or not os.path.isfile(stego_video):
            messagebox.showerror("Error", "Please select a valid stego video file.")
            return
        if not out_dir:
            messagebox.showerror("Error", "Please specify an output destination folder.")
            return

        self.btn_decrypt.configure(state="disabled")
        self.dec_prog_container.pack(fill="x", pady=(0, 8), before=self.btn_decrypt)
        self._update_dec_progress_ui(0.01, "Initializing decryption pipeline...")
        self.log(f"Starting decryption from '{os.path.basename(stego_video)}' using frame #{frame_no}...", "highlight")

        def _worker():
            try:
                pw_bytes = password_str.encode("utf-8")

                def _progress_cb(frac, msg=""):
                    self.after(0, lambda f=frac, m=msg: self._update_dec_progress_ui(f, m))

                recovered_path = video.decrypt_video(
                    stego_video,
                    out_dir,
                    pw_bytes,
                    frame_no,
                    progress_cb=_progress_cb
                )

                def _on_success():
                    self._update_dec_progress_ui(1.0, "Decryption Complete!")
                    self.btn_decrypt.configure(state="normal")
                    rec_size = os.path.getsize(recovered_path)
                    rec_name = os.path.basename(recovered_path)
                    self.log(f"Decryption SUCCESS: recovered '{rec_name}' ({format_size(rec_size)})", "success")

                    res = messagebox.askyesno(
                        "Decryption Successful",
                        f"Secret file recovered successfully!\n\n"
                        f"• Filename: {rec_name}\n"
                        f"• Size: {format_size(rec_size)}\n"
                        f"• Saved To: {recovered_path}\n\n"
                        "Would you like to open the recovered file now?"
                    )
                    if res:
                        open_file_directly(recovered_path)

                self.after(0, _on_success)
            except ValueError as ex:
                err_msg = str(ex)
                def _on_val_error():
                    self.dec_prog_lbl.configure(text=f"Authentication Failed")
                    self.btn_decrypt.configure(state="normal")
                    self.log(f"Decryption failed: {err_msg}", "error")
                    messagebox.showerror(
                        "Authentication Failed",
                        "Decryption failed.\n\n"
                        "Possible causes:\n"
                        "  1. Incorrect password\n"
                        "  2. Incorrect frame number (selected frame does not match encryption)\n"
                        "  3. Audio was truncated (e.g. force-embedded beyond carrier capacity)\n"
                        "  4. Audio track was re-encoded or modified with lossy compression\n"
                        "  5. The video does not contain a VFC payload."
                    )
                self.after(0, _on_val_error)
            except Exception as ex:
                err_msg = str(ex)
                def _on_gen_error():
                    self.dec_prog_lbl.configure(text=f"Error: {err_msg}")
                    self.btn_decrypt.configure(state="normal")
                    self.log(f"Decryption error: {err_msg}", "error")
                    messagebox.showerror("Decryption Error", f"An unexpected error occurred:\n\n{err_msg}")
                self.after(0, _on_gen_error)

        threading.Thread(target=_worker, daemon=True).start()

    # =========================================================================
    # TAB 3: TOOLS EVENT HANDLERS
    # =========================================================================
    def _browse_tool_conv_in(self):
        filename = filedialog.askopenfilename(
            title="Select Video to Convert",
            filetypes=[("Video Files", "*.mp4 *.mov *.avi *.webm *.mkv *.flv"), ("All Files", "*.*")]
        )
        if filename:
            self.tool_conv_in_var.set(filename)

    def _on_tool_conv_in_changed(self, *args):
        path = self.tool_conv_in_var.get().strip()
        if path and os.path.isfile(path) and not self.tool_conv_out_var.get():
            stem, _ = os.path.splitext(path)
            self.tool_conv_out_var.set(f"{stem}_carrier.mkv")

    def _browse_tool_conv_out(self):
        filename = filedialog.asksaveasfilename(
            title="Save VFC Carrier As",
            defaultextension=".mkv",
            filetypes=[("Matroska Video (*.mkv)", "*.mkv")]
        )
        if filename:
            self.tool_conv_out_var.set(filename)

    def _start_convert_carrier(self):
        in_video = self.tool_conv_in_var.get().strip()
        out_video = self.tool_conv_out_var.get().strip()

        if not in_video or not os.path.isfile(in_video):
            messagebox.showerror("Error", "Please select a valid input video to convert.")
            return
        if not out_video:
            messagebox.showerror("Error", "Please specify an output MKV video filename.")
            return

        self.btn_convert_carrier.configure(state="disabled")
        self.log(f"Converting '{os.path.basename(in_video)}' to PCM MKV carrier...", "highlight")

        def _worker():
            try:
                cmd = [
                    "ffmpeg", "-y", "-i", in_video,
                    "-c:v", "copy",
                    "-c:a", "pcm_s16le",
                    out_video
                ]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if res.returncode != 0:
                    raise RuntimeError(res.stderr or "ffmpeg conversion failed.")

                def _on_success():
                    self.btn_convert_carrier.configure(state="normal")
                    self.log(f"Conversion complete -> {out_video}", "success")
                    ans = messagebox.askyesno(
                        "Conversion Succeeded",
                        f"Carrier MKV created successfully!\n{out_video}\n\n"
                        "Would you like to set this as the active carrier in the Encrypt tab?"
                    )
                    if ans:
                        self.enc_carrier_var.set(out_video)
                        self.notebook.select(self.tab_encrypt)

                self.after(0, _on_success)
            except Exception as ex:
                err_msg = str(ex)
                def _on_error():
                    self.btn_convert_carrier.configure(state="normal")
                    self.log(f"Carrier conversion error: {err_msg}", "error")
                    messagebox.showerror("Conversion Failed", f"ffmpeg error:\n\n{err_msg}")
                self.after(0, _on_error)

        threading.Thread(target=_worker, daemon=True).start()

    def _browse_tool_insp(self):
        filename = filedialog.askopenfilename(
            title="Select Video to Inspect",
            filetypes=[("Video Files", "*.mkv *.mp4 *.mov *.avi *.webm"), ("All Files", "*.*")]
        )
        if filename:
            self.tool_insp_var.set(filename)
            self._inspect_video_capacity(filename)

    def _inspect_video_capacity(self, video_path: str):
        self.log(f"Inspecting audio track of '{os.path.basename(video_path)}'...", "info")
        self.insp_results_box.configure(state="normal")
        self.insp_results_box.delete("1.0", "end")
        self.insp_results_box.insert("1.0", "Extracting audio and calculating sample eligibility...")
        self.insp_results_box.configure(state="disabled")

        def _worker():
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    wav_path = os.path.join(tmp, "carrier.wav")
                    cmd = ["ffmpeg", "-y", "-i", video_path, "-vn", "-acodec", "pcm_s16le", wav_path]
                    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                    audio = WavAudio.load(wav_path)
                    eligible = audio.eligible_indices()
                    total_samples = len(audio.samples)
                    usable_bits = len(eligible)
                    usable_bytes = usable_bits // 8
                    outer_overhead = 50 + 32  # authenticated header + HMAC tag
                    ciphertext_capacity = (max(0, usable_bytes - outer_overhead) // 16) * 16
                    example_name = "secret.bin"
                    inner_metadata = 2 + len(example_name.encode("utf-8")) + 8 + 1
                    max_payload = max(0, ciphertext_capacity - inner_metadata - 1)
                    eligible_percent = (100.0 * len(eligible) / total_samples) if total_samples else 0.0

                    report = (
                        f"=== VFC Audio Steganography Capacity Report ===\n"
                        f"• Video: {os.path.basename(video_path)}\n"
                        f"• Sample Rate: {audio.params.framerate} Hz ({audio.params.nchannels} channel(s))\n"
                        f"• Total PCM Audio Samples: {total_samples:,}\n"
                        f"• Samples Eligible by |sample >> 1| >= 2: {len(eligible):,} ({eligible_percent:.1f}%)\n"
                        f"• Raw Audio Capacity: {format_size(usable_bytes)} (1 bit per eligible sample)\n"
                        f"• Largest Ciphertext That Fits: {format_size(ciphertext_capacity)} (whole 16-byte blocks)\n"
                        f"• Estimated Maximum Uncompressed File: {format_size(max_payload)}\n"
                        f"  Assumptions: filename '{example_name}', no compression; 82 bytes reserved for the outer header/tag,\n"
                        f"  then {inner_metadata} bytes for encrypted file metadata and at least 1 byte for PKCS#7 padding."
                    )

                    def _update_report():
                        self.insp_results_box.configure(state="normal")
                        self.insp_results_box.delete("1.0", "end")
                        self.insp_results_box.insert("1.0", report)
                        self.insp_results_box.configure(state="disabled")
                        self.log(f"Capacity inspection complete: {format_size(max_payload)} max secret capacity.", "success")

                    self.after(0, _update_report)
            except Exception as ex:
                err_msg = str(ex)
                def _report_error():
                    self.insp_results_box.configure(state="normal")
                    self.insp_results_box.delete("1.0", "end")
                    self.insp_results_box.insert("1.0", f"Inspection failed: {err_msg}")
                    self.insp_results_box.configure(state="disabled")
                    self.log(f"Inspection error: {err_msg}", "error")
                self.after(0, _report_error)

        threading.Thread(target=_worker, daemon=True).start()


def launch_gui():
    try:
        app = VfcGuiApp()
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    launch_gui()
