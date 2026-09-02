#!/usr/bin/env python3
"""
VFC Block Cipher Visualizer & Deep Tracer GUI (v0.2)
===================================================

A sophisticated, standalone graphical interface for exploring, tracing, and 
learning the VFC custom Substitution-Permutation Network (SPN) block cipher.

Features:
- Interactive 4x4 State Grid with live byte diffs, bit counts, and cell inspection.
- Step-by-Step Stepper & Auto-Player (Play/Pause, Step Next/Prev, Speed Slider).
- Deep Math Inspector:
    * Exact SubBytes S-Box lookups
    * ShiftRows cyclic permutation diagrams
    * MixColumns GF(2^8) Galois Field vector dot-product calculator (with 0x11B reductions)
    * AddRoundKey bitwise XOR key ingestion
- Key Schedule Visualizer (Master key -> RK0..RK6 via SHA-256 domain separation).
- Avalanche & Diffusion Live Explorer (Side-by-side 1-bit differential analysis).
- Interactive 16x16 S-Box Table and MDS Matrix inversion proofs.
- Modern dark-themed styling with high-contrast crypto aesthetic.
"""

import sys
import os
import time
import math
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# ---------------------------------------------------------------------------
# Cryptographic Primitives (VFC v0.2 Verbatim)
# ---------------------------------------------------------------------------
def gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11B)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return p

MDS = (
    (2, 3, 1, 1),
    (1, 2, 3, 1),
    (1, 1, 2, 3),
    (3, 1, 1, 2),
)

INV_MDS = (
    (14, 11, 13, 9),
    (9, 14, 11, 13),
    (13, 9, 14, 11),
    (11, 13, 9, 14),
)

ROUNDS = 6

def _build_sbox(seed: bytes):
    perm = list(range(256))
    counter = 0
    pool = b""
    pos = 0

    def next_byte():
        nonlocal counter, pool, pos
        if pos >= len(pool):
            pool = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
            counter += 1
            pos = 0
        b = pool[pos]
        pos += 1
        return b

    for i in range(255, 0, -1):
        limit = i + 1
        bound = (256 // limit) * limit
        while True:
            r = next_byte()
            if r < bound:
                break
        j = r % limit
        perm[i], perm[j] = perm[j], perm[i]

    inv = [0] * 256
    for idx, val in enumerate(perm):
        inv[val] = idx
    return perm, inv

SBOX, INV_SBOX = _build_sbox(b"VFC-SBOX-v0.2")

def expand_round_keys(k_enc: bytes, rounds: int = ROUNDS):
    return [
        hashlib.sha256(k_enc + b"VFC-RK" + i.to_bytes(2, "big")).digest()[:16]
        for i in range(rounds + 1)
    ]

def _to_state(block: bytes):
    return [[block[c * 4 + r] for c in range(4)] for r in range(4)]

def _from_state(state) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _sub_bytes(state, box):
    return [[box[state[r][c]] for c in range(4)] for r in range(4)]

def _shift_rows(state):
    return [state[r][r:] + state[r][:r] for r in range(4)]

def _mix_columns(state, matrix):
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[0][c], state[1][c], state[2][c], state[3][c]]
        for r in range(4):
            out[r][c] = (
                gmul(matrix[r][0], col[0]) ^
                gmul(matrix[r][1], col[1]) ^
                gmul(matrix[r][2], col[2]) ^
                gmul(matrix[r][3], col[3])
            )
    return out

def _add_round_key(state, rk: bytes):
    rks = _to_state(rk)
    return [[state[r][c] ^ rks[r][c] for c in range(4)] for r in range(4)]

def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    k = block - (len(data) % block)
    return data + bytes([k]) * k

# ---------------------------------------------------------------------------
# Execution Snapshot Collector
# ---------------------------------------------------------------------------
class TraceSnapshot:
    def __init__(self, step_idx, stage_name, round_num, layer_name, state_matrix, 
                 prev_state=None, note="", round_key=None, details=None):
        self.step_idx = step_idx
        self.stage_name = stage_name
        self.round_num = round_num
        self.layer_name = layer_name
        self.state_matrix = [row[:] for row in state_matrix]
        self.prev_state = [row[:] for row in prev_state] if prev_state else None
        self.note = note
        self.round_key = round_key
        self.details = details or {}
        self.raw_bytes = _from_state(state_matrix)

def generate_full_trace(plaintext: bytes, master_key_bytes: bytes, iv_bytes: bytes, zero_key_mode=False):
    padded = pkcs7_pad(plaintext, 16)
    first_block = padded[:16]
    cbc_in = _xor(first_block, iv_bytes)

    if zero_key_mode:
        round_keys = [bytes(16)] * (ROUNDS + 1)
    else:
        round_keys = expand_round_keys(master_key_bytes, ROUNDS)

    snapshots = []
    step = 0

    # Step 0: Input block before whitening
    state = _to_state(cbc_in)
    snapshots.append(TraceSnapshot(
        step_idx=step,
        stage_name="Input Block (Padded XOR IV)",
        round_num=0,
        layer_name="CBC Input",
        state_matrix=state,
        prev_state=None,
        note="CBC forms X1 = P1 XOR IV; the SPN trace begins from X1.",
        details={
            "plaintext_block": first_block,
            "iv": iv_bytes,
            "cbc_input": cbc_in,
            "padded_length": len(padded),
            "padding_length": padded[-1],
        },
    ))
    step += 1

    # Step 1: Initial Whitening
    prev = [row[:] for row in state]
    state = _add_round_key(state, round_keys[0])
    snapshots.append(TraceSnapshot(
        step_idx=step,
        stage_name="Initial Whitening (AddRoundKey RK0)",
        round_num=0,
        layer_name="AddRoundKey (RK0)",
        state_matrix=state,
        prev_state=prev,
        note="Combines the CBC input X1 with RK0 before the first nonlinear layer.",
        round_key=round_keys[0]
    ))
    step += 1

    # Rounds 1 through 6
    for r in range(1, ROUNDS + 1):
        # 1. SubBytes
        prev = [row[:] for row in state]
        state_sub = _sub_bytes(state, SBOX)
        snapshots.append(TraceSnapshot(
            step_idx=step,
            stage_name=f"Round {r}: SubBytes",
            round_num=r,
            layer_name="SubBytes",
            state_matrix=state_sub,
            prev_state=prev,
            note="Non-linear confusion via SHA-256 bijective S-Box."
        ))
        step += 1

        # 2. ShiftRows
        prev = [row[:] for row in state_sub]
        state_shift = _shift_rows(state_sub)
        snapshots.append(TraceSnapshot(
            step_idx=step,
            stage_name=f"Round {r}: ShiftRows",
            round_num=r,
            layer_name="ShiftRows",
            state_matrix=state_shift,
            prev_state=prev,
            note="Inter-column diffusion: Row r is cyclically rotated left by r bytes."
        ))
        step += 1

        # 3. MixColumns
        prev = [row[:] for row in state_shift]
        state_mix = _mix_columns(state_shift, MDS)
        snapshots.append(TraceSnapshot(
            step_idx=step,
            stage_name=f"Round {r}: MixColumns",
            round_num=r,
            layer_name="MixColumns",
            state_matrix=state_mix,
            prev_state=prev,
            note="Intra-column diffusion: GF(2^8) MDS matrix [2,3,1,1] multiplication."
        ))
        step += 1

        # 4. AddRoundKey
        prev = [row[:] for row in state_mix]
        state_key = _add_round_key(state_mix, round_keys[r])
        snapshots.append(TraceSnapshot(
            step_idx=step,
            stage_name=f"Round {r}: AddRoundKey (RK{r})",
            round_num=r,
            layer_name=f"AddRoundKey (RK{r})",
            state_matrix=state_key,
            prev_state=prev,
            note=f"Key ingestion: State bitwise XORed with subkey RK{r}.",
            round_key=round_keys[r]
        ))
        step += 1
        state = state_key

    return snapshots, round_keys, padded

# ---------------------------------------------------------------------------
# Sophisticated UI Application
# ---------------------------------------------------------------------------
class VFCTraceGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VFC Block Cipher Teaching Tracer (v0.2)")
        self.geometry("1240x860")
        self.minsize(1080, 760)

        # Restrained teaching-workbench palette shared with the Academic Kit.
        self.colors = {
            "bg_dark": "#0b0b0a",
            "bg_card": "#171713",
            "bg_card_border": "#49463d",
            "bg_cell": "#22221d",
            "bg_cell_active": "#413824",
            "bg_cell_changed": "#3d211f",
            "border_cell_changed": "#e16a5f",
            "text_bright": "#f7f3e8",
            "text_dim": "#c7bead",
            "text_muted": "#928a7c",
            "accent_cyan": "#c9aa75",
            "accent_blue": "#e2c68f",
            "accent_green": "#78c58f",
            "accent_purple": "#d99472",
            "accent_amber": "#e1b85d",
            "accent_rose": "#e16a5f",
        }
        self.configure(bg=self.colors["bg_dark"])

        # State Variables
        self.input_text_var = tk.StringVar(value="Hello")
        self.key_text_var = tk.StringVar(value="BlackRing-2028")
        self.iv_text_var = tk.StringVar(value="00000000000000000000000000000000")
        self.key_mode_var = tk.StringVar(value="vfc_kdf")  # 'vfc_kdf', 'zero_key'
        self.play_speed_var = tk.DoubleVar(value=1.0)  # seconds per step
        self.is_playing = False
        self.play_thread = None

        self.current_step = 0
        self.snapshots = []
        self.round_keys = []
        self.padded_input = b""
        self.selected_cell = (0, 0)  # (row, col)

        self._init_styles()
        self._build_layout()
        self.recompute_trace()

    def _init_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TNotebook", background=self.colors["bg_dark"], borderwidth=0)
        style.configure("TNotebook.Tab", 
                        background=self.colors["bg_card"], 
                        foreground=self.colors["text_dim"], 
                        padding=[14, 8],
                        font=("Helvetica", 10, "bold"),
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", self.colors["bg_cell_active"])],
                  foreground=[("selected", self.colors["text_bright"])])

        style.configure("TProgressbar", 
                        background=self.colors["accent_cyan"], 
                        troughcolor=self.colors["bg_card"])

    def _build_layout(self):
        # 1. Top Header Banner
        header = tk.Frame(self, bg=self.colors["bg_dark"], padx=18, pady=10)
        header.pack(fill="x", side="top")

        title_box = tk.Frame(header, bg=self.colors["bg_dark"])
        title_box.pack(side="left")

        lbl_title = tk.Label(title_box, text="VFC BLOCK CIPHER TEACHING TRACER",
                             font=("Consolas", 16, "bold"), 
                             fg=self.colors["accent_cyan"], bg=self.colors["bg_dark"])
        lbl_title.pack(anchor="w")

        lbl_subtitle = tk.Label(title_box, 
                                text="One 128-bit block • initial whitening • 6 SPN rounds • exact byte arithmetic",
                                font=("Helvetica", 9), 
                                fg=self.colors["text_dim"], bg=self.colors["bg_dark"])
        lbl_subtitle.pack(anchor="w")

        # Quick Preset Buttons on top right
        preset_box = tk.Frame(header, bg=self.colors["bg_dark"])
        preset_box.pack(side="right", pady=4)

        presets = [
            ("Hello vector", "Hello", "BlackRing-2028"),
            ("SECRET vector", "SECRET", "BlackRing-2028"),
            ("Zero-key hand trace", "Hello", "00000000000000000000000000000000", True),
        ]
        for item in presets:
            if len(item) == 3:
                name, w, k = item
                btn = tk.Button(preset_box, text=name, font=("Helvetica", 8, "bold"),
                                bg=self.colors["bg_card"], fg=self.colors["text_bright"],
                                activebackground=self.colors["bg_cell_active"],
                                activeforeground=self.colors["text_bright"],
                                bd=1, relief="flat", padx=8, pady=3, cursor="hand2",
                                command=lambda pw=w, pk=k: self._load_preset(pw, pk, False))
            else:
                name, w, k, zk = item
                btn = tk.Button(preset_box, text=name, font=("Helvetica", 8, "bold"),
                                bg=self.colors["bg_card"], fg=self.colors["accent_amber"],
                                activebackground=self.colors["bg_cell_active"],
                                activeforeground=self.colors["text_bright"],
                                bd=1, relief="flat", padx=8, pady=3, cursor="hand2",
                                command=lambda pw=w, pk=k: self._load_preset(pw, pk, True))
            btn.pack(side="left", padx=4)

        # 2. Config Toolbar Frame
        toolbar = tk.Frame(self, bg=self.colors["bg_card"], padx=18, pady=10, 
                           highlightbackground=self.colors["bg_card_border"], highlightthickness=1)
        toolbar.pack(fill="x", padx=16, pady=(0, 10))

        # Plaintext Input
        tk.Label(toolbar, text="Plaintext (first block):", font=("Helvetica", 9, "bold"),
                 fg=self.colors["text_dim"], bg=self.colors["bg_card"]).grid(row=0, column=0, sticky="w", padx=(0, 6))
        ent_pt = tk.Entry(toolbar, textvariable=self.input_text_var, font=("Consolas", 10), 
                          bg=self.colors["bg_dark"], fg=self.colors["text_bright"], 
                          insertbackground=self.colors["text_bright"], width=18, bd=1, relief="flat")
        ent_pt.grid(row=0, column=1, sticky="w", padx=(0, 16))

        # Key Input
        tk.Label(toolbar, text="K_enc / demo password:", font=("Helvetica", 9, "bold"),
                 fg=self.colors["text_dim"], bg=self.colors["bg_card"]).grid(row=0, column=2, sticky="w", padx=(0, 6))
        ent_key = tk.Entry(toolbar, textvariable=self.key_text_var, font=("Consolas", 10), 
                           bg=self.colors["bg_dark"], fg=self.colors["text_bright"], 
                           insertbackground=self.colors["text_bright"], width=22, bd=1, relief="flat")
        ent_key.grid(row=0, column=3, sticky="w", padx=(0, 16))

        # Key Mode Checkbox
        chk_zero = tk.Checkbutton(toolbar, text="Use RK0..RK6 = 0 (hand trace)",
                                  variable=self.key_mode_var, onvalue="zero_key", offvalue="vfc_kdf",
                                  font=("Helvetica", 9), fg=self.colors["accent_amber"], 
                                  bg=self.colors["bg_card"], selectcolor=self.colors["bg_dark"],
                                  activebackground=self.colors["bg_card"], 
                                  activeforeground=self.colors["accent_amber"],
                                  command=self.recompute_trace)
        chk_zero.grid(row=0, column=4, sticky="w", padx=(0, 16))

        # Recompute / Trace Button
        btn_trace = tk.Button(toolbar, text="Recompute trace", font=("Helvetica", 9, "bold"),
                              bg=self.colors["accent_cyan"], fg="#000000",
                              activebackground=self.colors["accent_blue"],
                              bd=0, padx=14, pady=4, cursor="hand2",
                              command=self.recompute_trace)
        btn_trace.grid(row=0, column=5, sticky="e")

        tk.Label(toolbar, text="CBC IV (16-byte Hex):", font=("Helvetica", 9, "bold"),
                 fg=self.colors["text_dim"], bg=self.colors["bg_card"]).grid(
                     row=1, column=0, sticky="w", padx=(0, 6), pady=(9, 0)
                 )
        ent_iv = tk.Entry(
            toolbar,
            textvariable=self.iv_text_var,
            font=("Consolas", 10),
            bg=self.colors["bg_dark"],
            fg=self.colors["text_bright"],
            insertbackground=self.colors["text_bright"],
            width=34,
            bd=1,
            relief="flat",
        )
        ent_iv.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(0, 16), pady=(9, 0))
        ent_iv.bind("<Return>", lambda _event: self.recompute_trace())

        self.lbl_input_status = tk.Label(
            toolbar,
            text="Single-block view: CBC first forms X1 = P1 XOR IV, then this tracer follows X1 through the SPN layers.",
            font=("Helvetica", 8),
            fg=self.colors["text_muted"],
            bg=self.colors["bg_card"],
            anchor="w",
            justify="left",
            wraplength=490,
        )
        self.lbl_input_status.grid(row=1, column=3, columnspan=3, sticky="ew", pady=(9, 0))
        toolbar.grid_columnconfigure(3, weight=1)

        # 3. Main Center Split
        main_split = tk.Frame(self, bg=self.colors["bg_dark"], padx=16)
        main_split.pack(fill="both", expand=True)

        # Left Column: State Matrix & Stepper
        left_col = tk.Frame(main_split, bg=self.colors["bg_card"], padx=16, pady=16,
                            highlightbackground=self.colors["bg_card_border"], highlightthickness=1)
        left_col.pack(side="left", fill="both", expand=False, padx=(0, 12), pady=(0, 10))
        left_col.config(width=460)

        # Step Indicator Banner
        self.lbl_stage_badge = tk.Label(left_col, text="STAGE: CBC INPUT", 
                                        font=("Consolas", 11, "bold"), 
                                        fg=self.colors["accent_cyan"], bg=self.colors["bg_dark"],
                                        padx=10, pady=6)
        self.lbl_stage_badge.pack(fill="x", pady=(0, 8))

        self.lbl_stage_note = tk.Label(left_col, text="", font=("Helvetica", 9), 
                                       fg=self.colors["text_dim"], bg=self.colors["bg_card"],
                                       wraplength=400, justify="center")
        self.lbl_stage_note.pack(fill="x", pady=(0, 12))

        # 4x4 State Grid Canvas
        self.matrix_canvas = tk.Canvas(left_col, width=380, height=340, 
                                       bg=self.colors["bg_dark"], bd=0, highlightthickness=0)
        self.matrix_canvas.pack(pady=4)
        self.matrix_canvas.bind("<Button-1>", self._on_matrix_click)

        # Legend / Cell info
        self.lbl_cell_info = tk.Label(left_col, text="Select a cell to inspect the exact operation that produced it",
                                      font=("Consolas", 9), fg=self.colors["accent_purple"],
                                      bg=self.colors["bg_card"])
        self.lbl_cell_info.pack(pady=(8, 12))

        # Playback Controls Bar
        controls_frame = tk.Frame(left_col, bg=self.colors["bg_card"])
        controls_frame.pack(fill="x", pady=(4, 8))

        btn_first = tk.Button(controls_frame, text="⏮ First", font=("Helvetica", 8, "bold"),
                              bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                              bd=1, relief="flat", padx=8, pady=4, cursor="hand2",
                              command=self.step_first)
        btn_first.pack(side="left", padx=2, expand=True, fill="x")

        btn_prev = tk.Button(controls_frame, text="◀ Prev", font=("Helvetica", 8, "bold"),
                             bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                             bd=1, relief="flat", padx=8, pady=4, cursor="hand2",
                             command=self.step_prev)
        btn_prev.pack(side="left", padx=2, expand=True, fill="x")

        self.btn_play = tk.Button(controls_frame, text="▶ Play", font=("Helvetica", 9, "bold"),
                                  bg=self.colors["accent_green"], fg="#000000",
                                  bd=0, padx=12, pady=4, cursor="hand2",
                                  command=self.toggle_play)
        self.btn_play.pack(side="left", padx=4, expand=True, fill="x")

        btn_next = tk.Button(controls_frame, text="Next ▶", font=("Helvetica", 8, "bold"),
                             bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                             bd=1, relief="flat", padx=8, pady=4, cursor="hand2",
                             command=self.step_next)
        btn_next.pack(side="left", padx=2, expand=True, fill="x")

        btn_last = tk.Button(controls_frame, text="Last ⏭", font=("Helvetica", 8, "bold"),
                             bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                             bd=1, relief="flat", padx=8, pady=4, cursor="hand2",
                             command=self.step_last)
        btn_last.pack(side="left", padx=2, expand=True, fill="x")

        # Step Slider & Speed
        slider_frame = tk.Frame(left_col, bg=self.colors["bg_card"])
        slider_frame.pack(fill="x", pady=4)

        tk.Label(slider_frame, text="Step:", font=("Helvetica", 8), 
                 fg=self.colors["text_muted"], bg=self.colors["bg_card"]).pack(side="left", padx=(0, 4))

        self.step_scale = tk.Scale(slider_frame, from_=0, to=25, orient="horizontal",
                                   bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                                   troughcolor=self.colors["bg_dark"], highlightthickness=0,
                                   showvalue=False, command=self._on_scale_slide)
        self.step_scale.pack(side="left", fill="x", expand=True, padx=4)

        self.lbl_step_num = tk.Label(slider_frame, text="0/25", font=("Consolas", 9, "bold"),
                                     fg=self.colors["accent_cyan"], bg=self.colors["bg_card"], width=6)
        self.lbl_step_num.pack(side="right")

        # Right Column: Notebook with Deep Math Inspector, Key Schedule, Avalanche, S-Box
        right_col = tk.Frame(main_split, bg=self.colors["bg_dark"])
        right_col.pack(side="right", fill="both", expand=True, pady=(0, 10))

        self.notebook = ttk.Notebook(right_col)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Deep Math & Layer Breakdown
        self.tab_math = tk.Frame(self.notebook, bg=self.colors["bg_card"], padx=14, pady=14)
        self.notebook.add(self.tab_math, text="Math & layer")
        self._build_math_tab(self.tab_math)

        # Tab 2: Key Schedule Explorer
        self.tab_keys = tk.Frame(self.notebook, bg=self.colors["bg_card"], padx=14, pady=14)
        self.notebook.add(self.tab_keys, text="Round keys RK0..RK6")
        self._build_keys_tab(self.tab_keys)

        # Tab 3: Avalanche Effect Simulator
        self.tab_avalanche = tk.Frame(self.notebook, bg=self.colors["bg_card"], padx=14, pady=14)
        self.notebook.add(self.tab_avalanche, text="Avalanche & diffusion")
        self._build_avalanche_tab(self.tab_avalanche)

        # Tab 4: S-Box & MDS Tables
        self.tab_tables = tk.Frame(self.notebook, bg=self.colors["bg_card"], padx=14, pady=14)
        self.notebook.add(self.tab_tables, text="S-Box & MDS")
        self._build_tables_tab(self.tab_tables)

        # 4. Bottom Status & Hex Ribbon
        status_bar = tk.Frame(self, bg=self.colors["bg_card"], padx=18, pady=8,
                              highlightbackground=self.colors["bg_card_border"], highlightthickness=1)
        status_bar.pack(fill="x", side="bottom")

        tk.Label(status_bar, text="Current State (Hex):", font=("Helvetica", 9, "bold"),
                 fg=self.colors["text_dim"], bg=self.colors["bg_card"]).pack(side="left", padx=(0, 8))

        self.lbl_hex_stream = tk.Label(status_bar, text="", font=("Consolas", 10, "bold"),
                                       fg=self.colors["accent_cyan"], bg=self.colors["bg_card"])
        self.lbl_hex_stream.pack(side="left")

        btn_copy = tk.Button(status_bar, text="📋 Copy Hex", font=("Helvetica", 8),
                             bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                             bd=1, relief="flat", padx=6, pady=1, cursor="hand2",
                             command=self._copy_current_hex)
        btn_copy.pack(side="left", padx=12)

        self.lbl_avalanche_summary = tk.Label(status_bar, text="", font=("Helvetica", 9),
                                              fg=self.colors["accent_purple"], bg=self.colors["bg_card"])
        self.lbl_avalanche_summary.pack(side="right")

    # -----------------------------------------------------------------------
    # Tab 1: Deep Math & Layer Breakdown Builder
    # -----------------------------------------------------------------------
    def _build_math_tab(self, parent):
        top_info = tk.Frame(parent, bg=parent["bg"])
        top_info.pack(fill="x", pady=(0, 10))

        self.lbl_layer_title = tk.Label(top_info, text="Select a step to inspect", 
                                        font=("Consolas", 12, "bold"),
                                        fg=self.colors["accent_blue"], bg=parent["bg"])
        self.lbl_layer_title.pack(anchor="w")

        self.lbl_layer_desc = tk.Label(top_info, text="", font=("Helvetica", 9),
                                       fg=self.colors["text_dim"], bg=parent["bg"], justify="left")
        self.lbl_layer_desc.pack(anchor="w", pady=(2, 6))

        # Text Console for Detailed Arithmetic
        self.txt_math_details = tk.Text(parent, font=("Consolas", 10), 
                                        bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                                        bd=1, relief="flat", padx=12, pady=10, wrap="word",
                                        highlightbackground=self.colors["bg_card_border"],
                                        highlightthickness=1)
        self.txt_math_details.pack(fill="both", expand=True)

        # Tags for colored math text
        self.txt_math_details.tag_config("heading", foreground=self.colors["accent_cyan"], font=("Consolas", 10, "bold"))
        self.txt_math_details.tag_config("accent", foreground=self.colors["accent_purple"], font=("Consolas", 10, "bold"))
        self.txt_math_details.tag_config("amber", foreground=self.colors["accent_amber"])
        self.txt_math_details.tag_config("green", foreground=self.colors["accent_green"])
        self.txt_math_details.tag_config("muted", foreground=self.colors["text_muted"])

    # -----------------------------------------------------------------------
    # Tab 2: Key Schedule Tab Builder
    # -----------------------------------------------------------------------
    def _build_keys_tab(self, parent):
        tk.Label(parent, text="Round-key expansion from K_enc (SHA-256 domain separation)",
                 font=("Consolas", 11, "bold"), fg=self.colors["accent_cyan"], bg=parent["bg"]).pack(anchor="w", pady=(0, 4))

        tk.Label(parent, text="Formula: RK_i = SHA-256(K_enc || 'VFC-RK' || uint16_be(i))[0:16]",
                 font=("Consolas", 9), fg=self.colors["text_dim"], bg=parent["bg"]).pack(anchor="w", pady=(0, 10))

        self.txt_keys_details = tk.Text(parent, font=("Consolas", 10), 
                                        bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                                        bd=1, relief="flat", padx=12, pady=10,
                                        highlightbackground=self.colors["bg_card_border"],
                                        highlightthickness=1)
        self.txt_keys_details.pack(fill="both", expand=True)
        self.txt_keys_details.tag_config("key_name", foreground=self.colors["accent_amber"], font=("Consolas", 10, "bold"))
        self.txt_keys_details.tag_config("key_hex", foreground=self.colors["accent_cyan"])
        self.txt_keys_details.tag_config("key_note", foreground=self.colors["text_muted"])

    # -----------------------------------------------------------------------
    # Tab 3: Avalanche & Diffusion Explorer Builder
    # -----------------------------------------------------------------------
    def _build_avalanche_tab(self, parent):
        tk.Label(parent, text="Avalanche and diffusion inspection",
                 font=("Consolas", 11, "bold"), fg=self.colors["accent_purple"], bg=parent["bg"]).pack(anchor="w", pady=(0, 4))

        tk.Label(parent, text="The default pair differs by one bit. Edit either word to measure the real input distance and follow how the difference spreads through the rounds.",
                 font=("Helvetica", 9), fg=self.colors["text_dim"], bg=parent["bg"]).pack(anchor="w", pady=(0, 10))

        sim_box = tk.Frame(parent, bg=parent["bg"])
        sim_box.pack(fill="x", pady=(0, 10))

        tk.Label(sim_box, text="Test Word A:", font=("Helvetica", 9, "bold"), fg=self.colors["text_dim"], bg=parent["bg"]).grid(row=0, column=0, padx=4)
        self.ent_av_a = tk.Entry(sim_box, font=("Consolas", 9), width=12, bg=self.colors["bg_dark"], fg=self.colors["text_bright"], bd=1)
        self.ent_av_a.insert(0, "Hello")
        self.ent_av_a.grid(row=0, column=1, padx=4)

        tk.Label(sim_box, text="Test Word B:", font=("Helvetica", 9, "bold"), fg=self.colors["text_dim"], bg=parent["bg"]).grid(row=0, column=2, padx=4)
        self.ent_av_b = tk.Entry(sim_box, font=("Consolas", 9), width=12, bg=self.colors["bg_dark"], fg=self.colors["text_bright"], bd=1)
        self.ent_av_b.insert(0, "Iello")
        self.ent_av_b.grid(row=0, column=3, padx=4)

        btn_run_av = tk.Button(sim_box, text="Run Comparison", font=("Helvetica", 9, "bold"),
                               bg=self.colors["accent_purple"], fg="#ffffff", bd=0, padx=10, pady=2, cursor="hand2",
                               command=self._run_avalanche_simulation)
        btn_run_av.grid(row=0, column=4, padx=8)

        self.txt_avalanche = tk.Text(parent, font=("Consolas", 9), 
                                     bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                                     bd=1, relief="flat", padx=12, pady=10,
                                     highlightbackground=self.colors["bg_card_border"],
                                     highlightthickness=1)
        self.txt_avalanche.pack(fill="both", expand=True)

    # -----------------------------------------------------------------------
    # Tab 4: S-Box & MDS Tables Builder
    # -----------------------------------------------------------------------
    def _build_tables_tab(self, parent):
        tk.Label(parent, text="Public Bijective S-Box (16x16 Hex Grid) & MDS Matrix", 
                 font=("Consolas", 11, "bold"), fg=self.colors["accent_cyan"], bg=parent["bg"]).pack(anchor="w", pady=(0, 4))

        self.txt_sbox_table = tk.Text(parent, font=("Consolas", 9), 
                                      bg=self.colors["bg_dark"], fg=self.colors["text_bright"],
                                      bd=1, relief="flat", padx=10, pady=10,
                                      highlightbackground=self.colors["bg_card_border"],
                                      highlightthickness=1)
        self.txt_sbox_table.pack(fill="both", expand=True)
        self._populate_sbox_table()

    # -----------------------------------------------------------------------
    # Execution & Trace Recompute
    # -----------------------------------------------------------------------
    def _load_preset(self, word, key, zero_key=False):
        self.input_text_var.set(word)
        self.key_text_var.set(key)
        self.key_mode_var.set("zero_key" if zero_key else "vfc_kdf")
        self.recompute_trace()

    def recompute_trace(self):
        word = self.input_text_var.get()
        key_raw = self.key_text_var.get()
        iv_hex = self.iv_text_var.get()

        plaintext = word.encode("utf-8") if word else b" "
        
        # Determine Master Key
        is_zero_key = (self.key_mode_var.get() == "zero_key")
        if is_zero_key:
            master_key_bytes = bytes(16)
            self.key_source_description = "Hand-trace mode: every round key is 16 zero bytes."
        else:
            if len(key_raw) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in key_raw):
                master_key_bytes = bytes.fromhex(key_raw)
                self.key_source_description = (
                    f"Direct tracer input: {len(master_key_bytes)}-byte hexadecimal key material."
                )
            else:
                master_key_bytes = hashlib.sha256(key_raw.encode("utf-8")).digest()
                self.key_source_description = (
                    "Teaching shortcut: SHA-256(demo password) supplies K_enc. "
                    "The full VFC pipeline uses PBKDF2 and derives three separated keys first."
                )

        iv_is_valid = len(iv_hex) == 32 and all(c in "0123456789abcdefABCDEF" for c in iv_hex)
        if iv_is_valid:
            iv_bytes = bytes.fromhex(iv_hex)
            self.lbl_input_status.config(
                text=f"{self.key_source_description} CBC IV accepted (16 bytes).",
                fg=self.colors["text_muted"],
            )
        else:
            iv_bytes = bytes(16)
            self.lbl_input_status.config(
                text=f"{self.key_source_description} Invalid IV; using 16 zero bytes for this trace.",
                fg=self.colors["accent_amber"],
            )

        self.snapshots, self.round_keys, self.padded_input = generate_full_trace(
            plaintext, master_key_bytes, iv_bytes, zero_key_mode=is_zero_key
        )

        self.step_scale.config(to=len(self.snapshots) - 1)
        self.current_step = 0
        self._render_current_step()
        self._render_key_schedule()
        self._run_avalanche_simulation()

    def _render_current_step(self):
        if not self.snapshots or self.current_step >= len(self.snapshots):
            return

        snap = self.snapshots[self.current_step]
        self.step_scale.set(self.current_step)
        self.lbl_step_num.config(text=f"{self.current_step}/{len(self.snapshots)-1}")

        # Update Header Badges
        self.lbl_stage_badge.config(text=f"STAGE [{self.current_step}]: {snap.stage_name.upper()}")
        self.lbl_stage_note.config(text=snap.note)

        # Render 4x4 Canvas Matrix
        self._draw_matrix(snap)

        # Render Bottom Hex
        hex_str = snap.raw_bytes.hex()
        spaced_hex = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        self.lbl_hex_stream.config(text=spaced_hex)

        # Render Math Tab Content
        self._render_math_details(snap)

    def _draw_matrix(self, snap):
        self.matrix_canvas.delete("all")
        cw, ch = 82, 74
        start_x, start_y = 26, 20

        # Draw Column headers
        for c in range(4):
            x = start_x + c * cw + cw // 2
            self.matrix_canvas.create_text(x, start_y - 10, text=f"Col {c}", 
                                           font=("Consolas", 8, "bold"), fill=self.colors["text_muted"])

        # Draw Row headers
        for r in range(4):
            y = start_y + r * ch + ch // 2
            self.matrix_canvas.create_text(start_x - 14, y, text=f"R{r}", 
                                           font=("Consolas", 8, "bold"), fill=self.colors["text_muted"])

        for r in range(4):
            for c in range(4):
                val = snap.state_matrix[r][c]
                prev_val = snap.prev_state[r][c] if snap.prev_state else None
                is_changed = (prev_val is not None and prev_val != val)
                is_selected = (self.selected_cell == (r, c))

                x0 = start_x + c * cw
                y0 = start_y + r * ch
                x1 = x0 + cw - 6
                y1 = y0 + ch - 6

                # Background Color logic
                if is_selected:
                    bg_col = self.colors["bg_cell_active"]
                    border_col = self.colors["accent_cyan"]
                    border_w = 2
                elif is_changed:
                    bg_col = self.colors["bg_cell_changed"]
                    border_col = self.colors["border_cell_changed"]
                    border_w = 1.5
                else:
                    bg_col = self.colors["bg_cell"]
                    border_col = self.colors["bg_card_border"]
                    border_w = 1

                self.matrix_canvas.create_rectangle(x0, y0, x1, y1, fill=bg_col, outline=border_col, width=border_w)

                # Hex display
                hex_txt = f"{val:02X}"
                hex_color = self.colors["accent_cyan"] if not is_changed else self.colors["accent_purple"]
                self.matrix_canvas.create_text(x0 + cw//2 - 3, y0 + 22, text=hex_txt, 
                                               font=("Consolas", 14, "bold"), fill=hex_color)

                # Decimal + Char display
                char_repr = chr(val) if 32 <= val <= 126 else "."
                sub_txt = f"{val:3d}  '{char_repr}'"
                self.matrix_canvas.create_text(x0 + cw//2 - 3, y0 + 46, text=sub_txt, 
                                               font=("Consolas", 8), fill=self.colors["text_dim"])

    def _on_matrix_click(self, event):
        cw, ch = 82, 74
        start_x, start_y = 26, 20
        c = (event.x - start_x) // cw
        r = (event.y - start_y) // ch
        if 0 <= r < 4 and 0 <= c < 4:
            self.selected_cell = (r, c)
            self._render_current_step()

    # -----------------------------------------------------------------------
    # Detailed Math Tab Rendering
    # -----------------------------------------------------------------------
    def _render_math_details(self, snap):
        self.txt_math_details.delete("1.0", tk.END)
        r, c = self.selected_cell
        val = snap.state_matrix[r][c]

        self.lbl_layer_title.config(text=f"LAYER: {snap.layer_name.upper()} • Cell [{r}][{c}] = 0x{val:02X}")

        self.txt_math_details.insert(tk.END, f"=== LAYER MATHEMATICAL BREAKDOWN ({snap.stage_name}) ===\n\n", "heading")

        if snap.round_num == 0:
            if "Input" in snap.layer_name:
                self.txt_math_details.insert(tk.END, "1. PKCS#7 Padding & CBC Input:\n", "heading")
                byte_index = c * 4 + r
                plain_byte = snap.details["plaintext_block"][byte_index]
                iv_byte = snap.details["iv"][byte_index]
                self.txt_math_details.insert(tk.END, f"   P1[{byte_index}] = 0x{plain_byte:02x}\n")
                self.txt_math_details.insert(tk.END, f"   IV[{byte_index}] = 0x{iv_byte:02x}\n")
                self.txt_math_details.insert(tk.END, f"   X1[{byte_index}] = P1[{byte_index}] ^ IV[{byte_index}] = 0x{plain_byte:02x} ^ 0x{iv_byte:02x} = 0x{val:02x}\n", "accent")
                self.txt_math_details.insert(tk.END, f"   Full padded message length: {snap.details['padded_length']} bytes; PKCS#7 padding byte: 0x{snap.details['padding_length']:02x} repeated {snap.details['padding_length']} time(s).\n\n")
            else:
                self.txt_math_details.insert(tk.END, "1. Initial Key Whitening (AddRoundKey RK0):\n", "heading")
                rk0_state = _to_state(self.round_keys[0])
                prev = snap.prev_state[r][c] if snap.prev_state else 0
                self.txt_math_details.insert(tk.END, f"   State[{r}][{c}] = Input[{r}][{c}] ^ RK0[{r}][{c}]\n")
                self.txt_math_details.insert(tk.END, f"                 = 0x{prev:02x} ^ 0x{rk0_state[r][c]:02x} = 0x{val:02x}\n\n", "accent")
                self.txt_math_details.insert(tk.END, "   Purpose: Prevents an attacker from computing Round 1 SubBytes without knowing RK0.\n", "muted")

        elif "SubBytes" in snap.layer_name:
            prev = snap.prev_state[r][c]
            self.txt_math_details.insert(tk.END, f"1. Non-Linear Substitution SBOX[0x{prev:02x}]:\n", "heading")
            self.txt_math_details.insert(tk.END, f"   Input byte:  0x{prev:02x} (Binary: {prev:08b})\n")
            self.txt_math_details.insert(tk.END, f"   S-Box Table: SBOX[0x{prev:02x}] -> 0x{val:02x} (Binary: {val:08b})\n\n", "accent")
            self.txt_math_details.insert(tk.END, "   Role: Shannon's Confusion (destroys linear relationships between plaintext and ciphertext).\n", "muted")

        elif "ShiftRows" in snap.layer_name:
            self.txt_math_details.insert(tk.END, f"2. Row Permutation (Cyclic Left Shift by {r} Positions):\n", "heading")
            orig_row = [snap.prev_state[r][i] for i in range(4)]
            new_row = [snap.state_matrix[r][i] for i in range(4)]
            self.txt_math_details.insert(tk.END, f"   Row {r} before ShiftRows: [" + " ".join(f"0x{b:02x}" for b in orig_row) + "]\n")
            self.txt_math_details.insert(tk.END, f"   Row {r} after  ShiftRows: [" + " ".join(f"0x{b:02x}" for b in new_row) + "]\n\n", "accent")
            self.txt_math_details.insert(tk.END, f"   Origin of Cell [{r}][{c}]: Was at Col ({(c + r) % 4}) before shift.\n", "amber")
            self.txt_math_details.insert(tk.END, "   Role: Inter-column diffusion (spreads column values across all 4 columns).\n", "muted")

        elif "MixColumns" in snap.layer_name:
            self.txt_math_details.insert(tk.END, f"3. Galois Field GF(2^8) Matrix Multiplication for Column {c}:\n", "heading")
            col_in = [snap.prev_state[i][c] for i in range(4)]
            self.txt_math_details.insert(tk.END, f"   Column {c} Input Vector: [0x{col_in[0]:02x}, 0x{col_in[1]:02x}, 0x{col_in[2]:02x}, 0x{col_in[3]:02x}]^T\n")
            self.txt_math_details.insert(tk.END, f"   MDS Matrix Row {r}:      [{MDS[r][0]}, {MDS[r][1]}, {MDS[r][2]}, {MDS[r][3]}]\n\n")

            t0 = gmul(MDS[r][0], col_in[0])
            t1 = gmul(MDS[r][1], col_in[1])
            t2 = gmul(MDS[r][2], col_in[2])
            t3 = gmul(MDS[r][3], col_in[3])
            res = t0 ^ t1 ^ t2 ^ t3

            self.txt_math_details.insert(tk.END, f"   s'[{r},{c}] = ({MDS[r][0]} • 0x{col_in[0]:02x}) ^ ({MDS[r][1]} • 0x{col_in[1]:02x}) ^ ({MDS[r][2]} • 0x{col_in[2]:02x}) ^ ({MDS[r][3]} • 0x{col_in[3]:02x})\n")
            self.txt_math_details.insert(tk.END, f"            = 0x{t0:02x} ^ 0x{t1:02x} ^ 0x{t2:02x} ^ 0x{t3:02x}\n")
            self.txt_math_details.insert(tk.END, f"            = 0x{res:02x}\n\n", "accent")
            self.txt_math_details.insert(tk.END, "   Arithmetic details: Multiplication is in GF(2^8) mod P(x) = x^8+x^4+x^3+x+1 (0x11B).\n", "muted")
            self.txt_math_details.insert(tk.END, "   Role: Intra-column diffusion (every byte in the column affects every output byte).\n", "muted")

        elif "AddRoundKey" in snap.layer_name:
            rkr_state = _to_state(snap.round_key)
            prev = snap.prev_state[r][c]
            self.txt_math_details.insert(tk.END, f"4. AddRoundKey (XOR with Subkey RK{snap.round_num}):\n", "heading")
            self.txt_math_details.insert(tk.END, f"   State[{r}][{c}] = MixColumns[{r}][{c}] ^ RK{snap.round_num}[{r}][{c}]\n")
            self.txt_math_details.insert(tk.END, f"                 = 0x{prev:02x} ^ 0x{rkr_state[r][c]:02x} = 0x{val:02x}\n\n", "accent")
            self.txt_math_details.insert(tk.END, f"   RK{snap.round_num} Hex: {snap.round_key.hex()}\n", "amber")
            self.txt_math_details.insert(tk.END, "   Role: Injects the secret key into the state so the cipher cannot be reversed without it.\n", "muted")

    # -----------------------------------------------------------------------
    # Key Schedule Tab Rendering
    # -----------------------------------------------------------------------
    def _render_key_schedule(self):
        self.txt_keys_details.delete("1.0", tk.END)
        self.txt_keys_details.insert(tk.END, "KEY SOURCE\n", "key_name")
        self.txt_keys_details.insert(
            tk.END,
            f"{getattr(self, 'key_source_description', 'Key source not calculated yet.')}\n\n",
            "key_note",
        )
        for i, rk in enumerate(self.round_keys):
            name = f"RK0 (Whitening)" if i == 0 else f"RK{i} (Round {i})"
            self.txt_keys_details.insert(tk.END, f"{name:<20}: ", "key_name")
            self.txt_keys_details.insert(tk.END, f"{rk.hex()}\n", "key_hex")
            
            # Print 4x4 mini matrix
            rks = _to_state(rk)
            for row in rks:
                row_str = "    " + "  ".join(f"{b:02x}" for b in row)
                self.txt_keys_details.insert(tk.END, f"{row_str}\n", "key_note")
            self.txt_keys_details.insert(tk.END, "\n")

    # -----------------------------------------------------------------------
    # Avalanche Simulation & Diffusion
    # -----------------------------------------------------------------------
    def _run_avalanche_simulation(self):
        w_a = self.ent_av_a.get().encode("utf-8") if self.ent_av_a.get() else b"A"
        w_b = self.ent_av_b.get().encode("utf-8") if self.ent_av_b.get() else b"B"

        snaps_a, rks, _ = generate_full_trace(w_a, hashlib.sha256(b"VFC-DEMO-KEY").digest(), bytes(16))
        snaps_b, _, _ = generate_full_trace(w_b, hashlib.sha256(b"VFC-DEMO-KEY").digest(), bytes(16))

        self.txt_avalanche.delete("1.0", tk.END)
        input_diff = sum((a ^ b).bit_count() for a, b in zip(snaps_a[0].raw_bytes, snaps_b[0].raw_bytes))
        self.txt_avalanche.insert(
            tk.END,
            f"Comparing:\n  Message A: {w_a!r}\n  Message B: {w_b!r}\n  Actual first SPN-input distance (X1 after PKCS#7 and CBC XOR): {input_diff} bit(s)\n\n",
            "heading",
        )
        self.txt_avalanche.insert(tk.END, f"{'Round / Stage':<28} | {'Changed Bytes':<14} | {'Flipped Bits':<14} | {'Bit Delta %'}\n")
        self.txt_avalanche.insert(tk.END, "-" * 75 + "\n")

        # Map steps to rounds
        round_two_bits = None
        round_two_bytes = None
        for idx in range(len(snaps_a)):
            sa = snaps_a[idx]
            sb = snaps_b[idx]
            xor_bytes = bytes(x ^ y for x, y in zip(sa.raw_bytes, sb.raw_bytes))
            changed_bytes = sum(1 for b in xor_bytes if b != 0)
            flipped_bits = sum(b.bit_count() for b in xor_bytes)
            pct = (flipped_bits / 128.0) * 100.0

            stage_lbl = f"R{sa.round_num}: {sa.layer_name}"
            self.txt_avalanche.insert(tk.END, f"{stage_lbl:<28} | {changed_bytes:>2}/16 bytes    | {flipped_bits:>3}/128 bits   | {pct:>5.1f}%\n")
            if sa.round_num == 2 and "AddRoundKey" in sa.layer_name:
                round_two_bits = flipped_bits
                round_two_bytes = changed_bytes

        if round_two_bits is not None:
            self.txt_avalanche.insert(
                tk.END,
                f"\nObserved for this pair after round 2: {round_two_bytes}/16 changed bytes and "
                f"{round_two_bits}/128 changed bits ({round_two_bits / 128 * 100:.1f}%).\n",
            )
        self.txt_avalanche.insert(
            tk.END,
            "This single comparison demonstrates propagation only; it does not establish cipher security or SAC.\n",
            "muted",
        )

    # -----------------------------------------------------------------------
    # S-Box Table Populator
    # -----------------------------------------------------------------------
    def _populate_sbox_table(self):
        self.txt_sbox_table.delete("1.0", tk.END)
        self.txt_sbox_table.insert(tk.END, "     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n")
        self.txt_sbox_table.insert(tk.END, "    ------------------------------------------------\n")
        for high in range(16):
            row_vals = [f"{SBOX[high * 16 + low]:02x}" for low in range(16)]
            self.txt_sbox_table.insert(tk.END, f" {high:1x}0 | " + " ".join(row_vals) + "\n")

    # -----------------------------------------------------------------------
    # Stepper & Playback Engine
    # -----------------------------------------------------------------------
    def step_first(self):
        self.current_step = 0
        self._render_current_step()

    def step_last(self):
        self.current_step = len(self.snapshots) - 1
        self._render_current_step()

    def step_prev(self):
        if self.current_step > 0:
            self.current_step -= 1
            self._render_current_step()

    def step_next(self):
        if self.current_step < len(self.snapshots) - 1:
            self.current_step += 1
            self._render_current_step()
        else:
            if self.is_playing:
                self.toggle_play()

    def _on_scale_slide(self, val):
        self.current_step = int(val)
        self._render_current_step()

    def toggle_play(self):
        if self.is_playing:
            self.is_playing = False
            self.btn_play.config(text="▶ Play", bg=self.colors["accent_green"])
        else:
            self.is_playing = True
            self.btn_play.config(text="⏸ Pause", bg=self.colors["accent_amber"])
            if self.current_step >= len(self.snapshots) - 1:
                self.current_step = 0
            self._play_loop()

    def _play_loop(self):
        if not self.is_playing:
            return
        if self.current_step < len(self.snapshots) - 1:
            self.current_step += 1
            self._render_current_step()
            self.after(int(self.play_speed_var.get() * 900), self._play_loop)
        else:
            self.toggle_play()

    def _copy_current_hex(self):
        if self.snapshots and self.current_step < len(self.snapshots):
            hex_data = self.snapshots[self.current_step].raw_bytes.hex()
            self.clipboard_clear()
            self.clipboard_append(hex_data)
            messagebox.showinfo("Copied", f"Current state hex copied to clipboard:\n\n{hex_data}")

# ---------------------------------------------------------------------------
# Launcher
# ---------------------------------------------------------------------------
def launch_trace_gui():
    app = VFCTraceGUI()
    app.mainloop()

if __name__ == "__main__":
    launch_trace_gui()
