# -*- coding: utf-8 -*-
"""
gui_main.py
─────────────────────────────────────────────────────────────────────────────
Tkinter GUI  —  MRV LX-5250 Console Server / PDU Manager
Author : Senior Software Engineer / Blue Team Security
Requires: mrv_backend.py in the same directory.

Threading model
───────────────
  Main thread    -> Tkinter event loop ONLY (never blocks).
  mrv-connect    -> MRVBackend.connect()  (blocks during auth).
  mrv-send-*     -> MRVBackend.send_command()  (short-lived).
  mrv-reader     -> MRVBackend.read_loop()  (persistent until disconnect).
  Worker -> UI   -> queue.Queue + root.after() drain (~60 Hz).
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable, Optional

from mrv_backend import (
    MRVAuthError,
    MRVBackend,
    MRVCommandError,
    MRVConnectionError,
)

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("mrv_gui.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("mrv.gui")

# ─────────────────────────────────────────────────────────────────────────────
# Design tokens
# ─────────────────────────────────────────────────────────────────────────────
BG_MAIN   = "#1a1a2e"
BG_PANEL  = "#16213e"
BG_ENTRY  = "#0f3460"
FG_LABEL  = "#c0cfe8"
FG_HEAD   = "#a0c4ff"
TERM_BG   = "#080808"
TERM_FG   = "lime"
TERM_FONT = ("Consolas", 10)
UI_FONT   = ("Segoe UI", 9)
BOLD_FONT = ("Segoe UI", 9, "bold")
MONO_FONT = ("Consolas", 10)

# Commands that require a confirmation dialog
_DESTRUCTIVE: frozenset[str] = frozenset({"OFF", "DELETE", "REBOOT"})


# ─────────────────────────────────────────────────────────────────────────────
# Widget helpers
# ─────────────────────────────────────────────────────────────────────────────
def _lighten(hex_color: str, by: float = 0.22) -> str:
    """Return a lighter version of hex_color for hover animation."""
    h = hex_color.lstrip("#")
    if len(h) != 6:
        return hex_color
    r, g, b = (int(h[i: i + 2], 16) for i in (0, 2, 4))
    return "#{:02x}{:02x}{:02x}".format(
        min(255, int(r + (255 - r) * by)),
        min(255, int(g + (255 - g) * by)),
        min(255, int(b + (255 - b) * by)),
    )


def _btn(
    parent: tk.Widget,
    text: str,
    color: str,
    command: Callable,
    width: int = 10,
    **kw,
) -> tk.Button:
    """Create a themed flat button with hover animation."""
    lighter = _lighten(color)
    b = tk.Button(
        parent,
        text=text,
        bg=color,
        fg="white",
        activebackground=lighter,
        activeforeground="white",
        relief="flat",
        font=BOLD_FONT,
        width=width,
        cursor="hand2",
        command=command,
        **kw,
    )
    b.bind("<Enter>", lambda _: b.config(bg=lighter))
    b.bind("<Leave>", lambda _: b.config(bg=color))
    return b


def _lbl(parent: tk.Widget, text: str, **kw) -> tk.Label:
    """Panel-background label with standard styling."""
    return tk.Label(parent, text=text, fg=FG_LABEL, bg=BG_PANEL, font=UI_FONT, **kw)


def _entry(
    parent: tk.Widget,
    var: tk.Variable,
    width: int = 18,
    **kw,
) -> tk.Entry:
    """Dark-themed entry widget."""
    return tk.Entry(
        parent,
        textvariable=var,
        bg=BG_ENTRY,
        fg="#e0e0e0",
        insertbackground="white",
        relief="flat",
        font=MONO_FONT,
        width=width,
        **kw,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main application
# ─────────────────────────────────────────────────────────────────────────────
class MRVApp:
    """
    5-tab Tkinter GUI for full MRV LX-5250 management.

    Layout (top to bottom)
    ──────────────────────
    Security warning banner  (always visible)
    ttk.Notebook             (5 tabs — controls locked until authenticated)
    Global output terminal   (ScrolledText, expands to fill window)
    Status bar               (connection state indicator)
    """

    POLL_MS = 16   # ~60 Hz UI refresh rate

    def __init__(self, root: tk.Tk) -> None:
        self._root    = root
        self._backend = MRVBackend()
        self._queue: queue.Queue[tuple] = queue.Queue()

        # Initialise control collections before any tab is built
        self._port_btns:   list[tk.Button] = []
        self._health_btns: list[tk.Button] = []
        self._cmd_widgets: list[tk.Widget] = []   # Tab 4 controls
        self._raw_widgets: list[tk.Widget] = []   # Tab 5 controls

        self._setup_window()
        self._setup_nb_style()
        self._build_ui()
        self._lock_controls(True)   # All controls disabled until auth
        self._root.after(self.POLL_MS, self._poll_queue)
        log.debug("GUI ready.")

    # ── Window & style ────────────────────────────────────────────────────────
    def _setup_window(self) -> None:
        self._root.title("MRV LX-5250  |  Console Server & PDU Manager")
        self._root.geometry("980x800")
        self._root.minsize(820, 660)
        self._root.configure(bg=BG_MAIN)
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_nb_style(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure(
            "Dark.TNotebook",
            background=BG_MAIN,
            borderwidth=0,
            tabmargins=[2, 5, 0, 0],
        )
        s.configure(
            "Dark.TNotebook.Tab",
            background="#0f3460",
            foreground=FG_LABEL,
            padding=[14, 7],
            font=BOLD_FONT,
        )
        s.map(
            "Dark.TNotebook.Tab",
            background=[("selected", "#0055bb"), ("active", "#1a4a80")],
            foreground=[("selected", "white"), ("active", FG_HEAD)],
        )

    # ── Top-level UI assembly ─────────────────────────────────────────────────
    def _build_ui(self) -> None:
        # 1. Permanent security warning banner
        tk.Label(
            self._root,
            text=(
                "  SECURITY WARNING: Cleartext Telnet Session Active. "
                "Sniffing Risk!  "
            ),
            fg="white",
            bg="#8b0000",
            font=("Consolas", 9, "bold"),
            pady=5,
            anchor="center",
        ).pack(fill="x", side="top")

        # 2. Notebook
        self._nb = ttk.Notebook(self._root, style="Dark.TNotebook")
        self._nb.pack(fill="x", padx=10, pady=(6, 2))

        self._build_tab_connection()
        self._build_tab_port_control()
        self._build_tab_system_health()
        self._build_tab_cmd_builder()
        self._build_tab_raw_terminal()

        # 3. Global terminal (expands with window)
        self._build_terminal()

        # 4. Status bar
        self._build_statusbar()

    # ── Tab 1: Connection & Auth ──────────────────────────────────────────────
    def _build_tab_connection(self) -> None:
        f = tk.Frame(self._nb, bg=BG_PANEL, padx=14, pady=10)
        self._nb.add(f, text="  Connection  ")

        # Row A — IP and Port
        row_a = tk.Frame(f, bg=BG_PANEL)
        row_a.pack(fill="x", pady=3)
        _lbl(row_a, "Device IP:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._v_ip = tk.StringVar(value="192.168.1.252")
        _entry(row_a, self._v_ip, 18).grid(row=0, column=1, sticky="w")
        _lbl(row_a, "   Port:").grid(row=0, column=2, sticky="w", padx=(12, 6))
        self._v_port = tk.StringVar(value="23")
        _entry(row_a, self._v_port, 6).grid(row=0, column=3, sticky="w")

        # Row B — Username and Password
        row_b = tk.Frame(f, bg=BG_PANEL)
        row_b.pack(fill="x", pady=3)
        _lbl(row_b, "Username:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._v_user = tk.StringVar(value="Admn")
        _entry(row_b, self._v_user, 18).grid(row=0, column=1, sticky="w")
        _lbl(row_b, "   Password:").grid(row=0, column=2, sticky="w", padx=(12, 6))
        self._v_pass = tk.StringVar()
        _entry(row_b, self._v_pass, 18, show="*").grid(row=0, column=3, sticky="w")

        # Buttons
        btn_row = tk.Frame(f, bg=BG_PANEL)
        btn_row.pack(fill="x", pady=(10, 4))

        self._btn_connect = _btn(
            btn_row, "  Connect  ", "#0055cc", self._on_connect, width=14
        )
        self._btn_connect.pack(side="left", padx=(0, 10))

        self._btn_disconnect = _btn(
            btn_row, "Disconnect", "#880000", self._on_disconnect, width=14
        )
        self._btn_disconnect.pack(side="left")
        self._btn_disconnect.config(state="disabled")

        # Status
        self._lbl_conn = tk.Label(
            f, text="  Not connected", fg="#ff5555", bg=BG_PANEL, font=BOLD_FONT
        )
        self._lbl_conn.pack(anchor="w", pady=(6, 0))

    # ── Tab 2: Quick Port Control ─────────────────────────────────────────────
    def _build_tab_port_control(self) -> None:
        f = tk.Frame(self._nb, bg=BG_PANEL, padx=14, pady=10)
        self._nb.add(f, text="  Port Control  ")

        _lbl(f, "Control a PDU outlet port (1-8):").pack(anchor="w", pady=(0, 8))

        # Port ID entry with widget-level keystroke validation
        pid_row = tk.Frame(f, bg=BG_PANEL)
        pid_row.pack(fill="x", pady=3)
        _lbl(pid_row, "Port ID (1-8):").pack(side="left", padx=(0, 10))

        vcmd = (self._root.register(self._validate_port_id), "%P")
        self._v_port_id = tk.StringVar()
        self._ent_port_id = tk.Entry(
            pid_row,
            textvariable=self._v_port_id,
            validate="key",
            validatecommand=vcmd,
            width=4,
            bg=BG_ENTRY,
            fg="#e0e0e0",
            insertbackground="white",
            relief="flat",
            font=("Consolas", 14, "bold"),
        )
        self._ent_port_id.pack(side="left")

        # Action buttons
        act_row = tk.Frame(f, bg=BG_PANEL)
        act_row.pack(fill="x", pady=(10, 0))

        port_actions = [
            ("  ON  ", "#006622"),
            ("  OFF  ", "#880000"),
            (" REBOOT ", "#664400"),
            ("CONNECT", "#004488"),
        ]
        for label, color in port_actions:
            cmd = label.strip()
            b = _btn(
                act_row, label, color,
                lambda c=cmd: self._on_port_cmd(c),
                width=10,
            )
            b.pack(side="left", padx=(0, 6))
            self._port_btns.append(b)

        tk.Label(
            f,
            text=(
                "ON / OFF  =  apply or remove outlet power.\n"
                "REBOOT    =  power-cycle the outlet (OFF then ON).\n"
                "CONNECT   =  open reverse Telnet to the connected device."
            ),
            fg="#6688aa",
            bg=BG_PANEL,
            font=("Segoe UI", 8),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))

    # ── Tab 3: System Health ──────────────────────────────────────────────────
    def _build_tab_system_health(self) -> None:
        f = tk.Frame(self._nb, bg=BG_PANEL, padx=14, pady=10)
        self._nb.add(f, text="  System Health  ")

        _lbl(f, "Query device health (no parameters):").pack(anchor="w", pady=(0, 8))

        btn_row = tk.Frame(f, bg=BG_PANEL)
        btn_row.pack(fill="x")

        health_cmds = [
            ("STATUS",  "#1a4a7a"),
            ("ISTAT",   "#1a4a7a"),
            ("ENVMON",  "#2a4422"),
            ("VERSION", "#2a4422"),
        ]
        for cmd, color in health_cmds:
            b = _btn(
                btn_row, cmd, color,
                lambda c=cmd: self._on_sys_cmd(c),
                width=10,
            )
            b.pack(side="left", padx=(0, 6))
            self._health_btns.append(b)

        tk.Label(
            f,
            text=(
                "STATUS  : outlet power state summary.\n"
                "ISTAT   : input power / current draw.\n"
                "ENVMON  : environmental sensors (temperature, humidity).\n"
                "VERSION : firmware and hardware version strings."
            ),
            fg="#6688aa",
            bg=BG_PANEL,
            font=("Segoe UI", 8),
            justify="left",
        ).pack(anchor="w", pady=(12, 0))

    # ── Tab 4: Hierarchical Command Builder ───────────────────────────────────
    def _build_tab_cmd_builder(self) -> None:
        f = tk.Frame(self._nb, bg=BG_PANEL, padx=14, pady=10)
        self._nb.add(f, text="  Command Builder  ")

        _lbl(f, "Build and execute structured commands:").pack(anchor="w", pady=(0, 8))

        row = tk.Frame(f, bg=BG_PANEL)
        row.pack(fill="x", pady=4)

        _lbl(row, "Command:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._v_cb_cmd = tk.StringVar(value="LIST")
        self._cb_cmd = ttk.Combobox(
            row,
            textvariable=self._v_cb_cmd,
            values=["LIST", "SHOW", "SET", "CREATE", "DELETE", "PING", "RESTART"],
            state="readonly",
            width=10,
            font=MONO_FONT,
        )
        self._cb_cmd.grid(row=0, column=1, sticky="w")
        self._cmd_widgets.append(self._cb_cmd)

        _lbl(row, "  Parameter / Sub-command:").grid(
            row=0, column=2, sticky="w", padx=(14, 6)
        )
        self._v_cmd_param = tk.StringVar()
        ent = tk.Entry(
            row,
            textvariable=self._v_cmd_param,
            bg=BG_ENTRY,
            fg="#e0e0e0",
            insertbackground="white",
            relief="flat",
            font=MONO_FONT,
            width=22,
        )
        ent.grid(row=0, column=3, sticky="w")
        self._cmd_widgets.append(ent)

        self._btn_execute = _btn(
            f, "  EXECUTE COMMAND  ", "#0044aa",
            self._on_execute_cmd, width=22,
        )
        self._btn_execute.pack(anchor="w", pady=(10, 0))
        self._cmd_widgets.append(self._btn_execute)

        tk.Label(
            f,
            text=(
                "Examples:\n"
                "  LIST    PORTS            — list all outlets\n"
                "  PING    192.168.1.1      — ping from device\n"
                "  SET     PORT 1 NAME WEB  — rename outlet 1\n"
                "  CREATE  USER bob         — create user account\n"
                "  DELETE  USER bob         — destroy user (REQUIRES CONFIRM)"
            ),
            fg="#6688aa",
            bg=BG_PANEL,
            font=("Segoe UI", 8),
            justify="left",
        ).pack(anchor="w", pady=(10, 0))

    # ── Tab 5: Raw Terminal ───────────────────────────────────────────────────
    def _build_tab_raw_terminal(self) -> None:
        f = tk.Frame(self._nb, bg=BG_PANEL, padx=14, pady=10)
        self._nb.add(f, text="  Raw Terminal  ")

        _lbl(f, "Send any command string directly to the device CLI:").pack(
            anchor="w", pady=(0, 8)
        )

        row = tk.Frame(f, bg=BG_PANEL)
        row.pack(fill="x", pady=4)

        _lbl(row, "CMD:").pack(side="left", padx=(0, 8))

        self._v_raw = tk.StringVar()
        ent_raw = tk.Entry(
            row,
            textvariable=self._v_raw,
            bg=BG_ENTRY,
            fg="#e0e0e0",
            insertbackground="white",
            relief="flat",
            font=MONO_FONT,
            width=42,
        )
        ent_raw.pack(side="left", padx=(0, 10))
        ent_raw.bind("<Return>", lambda _: self._on_send_raw())
        self._raw_widgets.append(ent_raw)

        btn_raw = _btn(row, "SEND RAW", "#553300", self._on_send_raw, width=12)
        btn_raw.pack(side="left")
        self._raw_widgets.append(btn_raw)

        tk.Label(
            f,
            text=(
                "  Bypasses all input validation. Simulates a real CLI session.\n"
                "  Use with extreme caution on production equipment."
            ),
            fg="#ff8844",
            bg=BG_PANEL,
            font=("Segoe UI", 8, "italic"),
        ).pack(anchor="w", pady=(8, 0))

    # ── Global output terminal ────────────────────────────────────────────────
    def _build_terminal(self) -> None:
        outer = tk.LabelFrame(
            self._root,
            text="  Device Output Terminal  ",
            fg=FG_HEAD,
            bg=BG_PANEL,
            font=BOLD_FONT,
            bd=2,
            relief="groove",
            padx=6,
            pady=6,
        )
        outer.pack(fill="both", expand=True, padx=10, pady=(2, 4))

        self._term = scrolledtext.ScrolledText(
            outer,
            bg=TERM_BG,
            fg=TERM_FG,
            insertbackground=TERM_FG,
            font=TERM_FONT,
            relief="flat",
            state="disabled",
            wrap="word",
        )
        self._term.pack(fill="both", expand=True)

        self._term.tag_config("info",  foreground="#88ccff")
        self._term.tag_config("warn",  foreground="#ffcc44")
        self._term.tag_config("error", foreground="#ff5555")
        self._term.tag_config("cmd",   foreground="#aaffaa")

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_statusbar(self) -> None:
        bar = tk.Frame(self._root, bg="#080808", height=24)
        bar.pack(fill="x", side="bottom")
        self._lbl_status = tk.Label(
            bar,
            text="  Disconnected",
            fg="#ff4444",
            bg="#080808",
            font=UI_FONT,
            anchor="w",
            padx=10,
        )
        self._lbl_status.pack(side="left", fill="y")

    # ── Input validation ──────────────────────────────────────────────────────
    @staticmethod
    def _validate_port_id(proposed: str) -> bool:
        """
        Keystroke validator for the Port ID entry.
        Accepts empty string or a single digit in [1, 8].

        Args:
            proposed: Entry content after the proposed keystroke.

        Returns:
            True to accept the keystroke, False to reject.
        """
        if proposed == "":
            return True
        if len(proposed) > 1:
            return False
        return proposed.isdigit() and 1 <= int(proposed) <= 8

    def _resolve_port_id(self) -> Optional[int]:
        """
        Read and validate the Port ID entry (secondary, pre-send check).

        Returns:
            int in [1, 8], or None if invalid (error written to terminal).
        """
        raw = self._v_port_id.get().strip()
        if not raw:
            self._term_write("[INPUT] Port ID is empty — enter 1-8.\n", "error")
            return None
        if not raw.isdigit() or not (1 <= int(raw) <= 8):
            self._term_write(
                f"[INPUT] '{raw}' rejected — only integers 1-8 are accepted.\n",
                "error",
            )
            return None
        return int(raw)

    # ── Event handlers (all on main thread) ───────────────────────────────────
    def _on_connect(self) -> None:
        """Validate fields then launch the connect worker thread."""
        host     = self._v_ip.get().strip()
        port_str = self._v_port.get().strip()
        user     = self._v_user.get().strip()
        passwd   = self._v_pass.get()

        if not host:
            messagebox.showwarning("Missing Input", "Device IP cannot be empty.")
            return
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            messagebox.showwarning("Invalid Port", "Port must be an integer 1-65535.")
            return
        if not user:
            messagebox.showwarning("Missing Input", "Username cannot be empty.")
            return

        self._term_write(
            f"[INFO] Connecting to {host}:{port_str} as '{user}' ...\n", "info"
        )
        self._set_conn_status("Connecting ...", "#ffcc44")
        self._btn_connect.config(state="disabled")
        self._btn_disconnect.config(state="normal")

        threading.Thread(
            target=self._worker_connect,
            args=(host, int(port_str), user, passwd),
            daemon=True,
            name="mrv-connect",
        ).start()

    def _on_disconnect(self) -> None:
        threading.Thread(
            target=self._worker_disconnect,
            daemon=True,
            name="mrv-disconnect",
        ).start()

    def _on_port_cmd(self, cmd: str) -> None:
        """Validate Port ID, optionally confirm, then dispatch."""
        pid = self._resolve_port_id()
        if pid is None:
            return
        if cmd in _DESTRUCTIVE:
            if not messagebox.askyesno(
                f"Confirm {cmd}",
                f"Execute '{cmd}' on Port {pid}?\n\n"
                "This may immediately disrupt a live device.",
                icon="warning",
            ):
                self._term_write(
                    f"[CANCELLED] {cmd} {pid} — aborted by operator.\n", "warn"
                )
                return
        self._dispatch(f"{cmd} {pid}")

    def _on_sys_cmd(self, cmd: str) -> None:
        self._dispatch(cmd)

    def _on_execute_cmd(self) -> None:
        """Validate, optionally confirm destructive command, then dispatch."""
        cmd   = self._v_cb_cmd.get().strip()
        param = self._v_cmd_param.get().strip()
        full  = f"{cmd} {param}".strip() if param else cmd

        if cmd in _DESTRUCTIVE:
            if not messagebox.askyesno(
                f"Confirm {cmd}",
                f"Execute: '{full}'\n\n"
                "This command may be destructive. Proceed?",
                icon="warning",
            ):
                self._term_write(
                    f"[CANCELLED] '{full}' — aborted by operator.\n", "warn"
                )
                return
        self._dispatch(full)

    def _on_send_raw(self) -> None:
        raw = self._v_raw.get().strip()
        if not raw:
            return
        self._v_raw.set("")
        self._dispatch(raw)

    def _on_close(self) -> None:
        log.info("Window closing.")
        self._backend.disconnect()
        self._root.destroy()

    # ── Dispatch helper ───────────────────────────────────────────────────────
    def _dispatch(self, cmd: str) -> None:
        """Send a command via a short-lived daemon thread."""
        threading.Thread(
            target=self._worker_send,
            args=(cmd,),
            daemon=True,
            name="mrv-send",
        ).start()

    # ── Worker threads (NOT main thread) ─────────────────────────────────────
    def _worker_connect(
        self, host: str, port: int, user: str, passwd: str
    ) -> None:
        try:
            self._backend.connect(
                host=host,
                port=port,
                username=user,
                password=passwd,
                on_data=self._q_data,
            )
        except MRVConnectionError as exc:
            self._q_write(f"[CONN ERROR] {exc}\n", "error")
            self._q_call(self._reset_disconnected)
            return
        except MRVAuthError as exc:
            self._q_write(f"[AUTH ERROR] {exc}\n", "error")
            self._q_call(self._reset_disconnected)
            return
        except Exception as exc:  # noqa: BLE001
            self._q_write(f"[ERROR] Unexpected: {exc}\n", "error")
            self._q_call(self._reset_disconnected)
            log.exception("Unexpected error in connect worker.")
            return

        self._q_write(
            "[INFO]  Authentication successful — controls unlocked.\n", "info"
        )
        self._q_call(self._on_auth_ok)

        threading.Thread(
            target=self._backend.read_loop,
            kwargs={
                "on_data": self._q_data,
                "on_disconnect": lambda: self._q_call(self._reset_disconnected),
            },
            daemon=True,
            name="mrv-reader",
        ).start()

    def _worker_disconnect(self) -> None:
        self._backend.disconnect()
        self._q_write("[INFO] Disconnected by operator.\n", "info")
        self._q_call(self._reset_disconnected)

    def _worker_send(self, cmd: str) -> None:
        try:
            self._q_write(f"\n[CMD] > {cmd}\n", "cmd")
            self._backend.send_command(cmd)
        except MRVCommandError as exc:
            self._q_write(f"[CMD ERROR] {exc}\n", "error")

    # ── Queue / UI bridge ─────────────────────────────────────────────────────
    def _q_data(self, data: bytes) -> None:
        """Decode raw bytes from worker thread and push to queue."""
        self._queue.put(("write", data.decode("utf-8", errors="ignore"), None))

    def _q_write(self, text: str, tag: Optional[str] = None) -> None:
        self._queue.put(("write", text, tag))

    def _q_call(self, fn: Callable) -> None:
        self._queue.put(("call", fn, None))

    def _poll_queue(self) -> None:
        """Drain up to 300 items per tick (main thread, ~60 Hz)."""
        for _ in range(300):
            try:
                kind, payload, tag = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "write":
                self._term_write(payload, tag)
            elif kind == "call":
                payload()
        self._root.after(self.POLL_MS, self._poll_queue)

    # ── Terminal write (main thread only) ─────────────────────────────────────
    def _term_write(self, text: str, tag: Optional[str] = None) -> None:
        self._term.config(state="normal")
        if tag:
            self._term.insert("end", text, tag)
        else:
            self._term.insert("end", text)
        self._term.see("end")
        self._term.config(state="disabled")

    # ── UI state (main thread only) ───────────────────────────────────────────
    def _set_conn_status(self, text: str, color: str) -> None:
        self._lbl_conn.config(text=f"  {text}", fg=color)
        self._lbl_status.config(text=f"  {text}", fg=color)

    def _lock_controls(self, locked: bool) -> None:
        """Enable/disable all post-auth controls across all tabs."""
        state = "disabled" if locked else "normal"

        for b in self._port_btns:
            b.config(state=state)
        self._ent_port_id.config(state=state)

        for b in self._health_btns:
            b.config(state=state)

        for w in self._cmd_widgets:
            w.config(state=state if not isinstance(w, ttk.Combobox) else "readonly" if not locked else "disabled")

        for w in self._raw_widgets:
            w.config(state=state)

    def _on_auth_ok(self) -> None:
        self._lock_controls(False)
        self._set_conn_status("Connected & Authenticated", "#44ff88")

    def _reset_disconnected(self) -> None:
        self._lock_controls(True)
        self._btn_connect.config(state="normal")
        self._btn_disconnect.config(state="disabled")
        self._set_conn_status("Disconnected", "#ff4444")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    """Launch the MRV LX-5250 Manager GUI."""
    root = tk.Tk()
    _app = MRVApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
