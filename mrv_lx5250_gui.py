# -*- coding: utf-8 -*-
"""
mrv_lx5250_gui.py
─────────────────────────────────────────────────────────────────────────────
MRV LX-5250 Console Server / Switched PDU — Telnet Management GUI
Author : Senior Software Engineer / Blue Team Security
Python : 3.10+  |  Stdlib only (tkinter, threading, queue, socket, logging)
Note   : telnetlib was removed in Python 3.13. IAC negotiation is implemented
         manually via TelnetIACHandler to remain compatible with Python 3.13+.

Architecture
────────────
• MRVBackend  – stateful Telnet client (state machine: IDLE→CONNECTING→AUTH→READY)
• MRVApp      – Tkinter GUI; all network I/O delegated to daemon worker threads;
                UI updates sent back via queue + root.after() poll loop (~60 Hz).

Security notes (Blue Team)
──────────────────────────
• Input validation: Port ID 1-8 enforced at widget level AND before socket send.
• Destructive commands (OFF) trigger confirmation dialog before any bytes sent.
• Permanent security-warning banner reminds operators Telnet is cleartext.
• Credentials are never written to log; only sanitised echoes appear in terminal.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
import queue
import select
import socket
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Logging — file + stderr; credentials never printed
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("mrv_gui.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("mrv_lx5250")


# ─────────────────────────────────────────────────────────────────────────────
# Custom Exceptions
# ─────────────────────────────────────────────────────────────────────────────
class MRVAuthError(Exception):
    """Raised when authentication fails or times out."""


class MRVConnectionError(Exception):
    """Raised when the TCP connection cannot be established."""


class MRVCommandError(Exception):
    """Raised when a command cannot be sent (not authenticated or socket gone)."""


# ─────────────────────────────────────────────────────────────────────────────
# RFC 854 Telnet IAC Negotiation Handler
# ─────────────────────────────────────────────────────────────────────────────
# telnetlib was deprecated in Python 3.11 and REMOVED in Python 3.13.
# This handler strips and responds to IAC option negotiation so that
# clean ASCII prompts ('Username: ', 'Password: ', 'LX: ') are visible.
#
# IAC command bytes (RFC 854)
_IAC:  int = 0xFF   # Interpret As Command
_WILL: int = 0xFB   # I will use option X
_WONT: int = 0xFC   # I won't use option X
_DO:   int = 0xFD   # Please use option X
_DONT: int = 0xFE   # Don't use option X
_SB:   int = 0xFA   # Sub-negotiation begin
_SE:   int = 0xF0   # Sub-negotiation end


class TelnetIACHandler:
    """
    Wraps a raw TCP socket and transparently handles Telnet IAC negotiation.

    Policy: reply DONT to all WILL offers, WONT to all DO requests.
    This puts both sides in a minimal-feature, NVT-compatible mode
    (no linemode, no echo option conflicts) which is all we need for
    a command-line PDU session.

    Usage
    ─────
    handler = TelnetIACHandler(sock)
    clean   = handler.read(4096, timeout=5.0)   # IAC stripped, replies sent
    handler.write(b"Admn\r\n")                  # raw write, no IAC escaping
    """

    BUFFER_SIZE: int = 4096

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._clean_buf = bytearray()  # clean decoded bytes, IAC stripped
        self._raw_buf   = bytearray()  # raw bytes not yet parsed
        log.debug("TelnetIACHandler attached to socket.")

    def write(self, data: bytes) -> None:
        """
        Send bytes to the device (escape any 0xFF as 0xFF 0xFF per RFC 854).

        Args:
            data: Bytes to transmit.

        Raises:
            MRVCommandError: If the send fails.
        """
        # Escape literal 0xFF bytes in outbound data
        escaped = data.replace(bytes([_IAC]), bytes([_IAC, _IAC]))
        try:
            self._sock.sendall(escaped)
        except OSError as exc:
            raise MRVCommandError(f"Write failed: {exc}") from exc

    def read(self, n: int = BUFFER_SIZE, timeout: float = 2.0) -> bytes:
        """
        Read up to *n* clean bytes (IAC stripped) from the socket.

        Blocks for up to *timeout* seconds per recv call; returns immediately
        if there is already clean data buffered.

        Args:
            n:       Maximum clean bytes to return.
            timeout: Per-recv socket timeout in seconds.

        Returns:
            Up to *n* clean bytes (may be fewer or empty on timeout).

        Raises:
            MRVAuthError: If the socket closes unexpectedly.
        """
        # If already have clean data buffered, return it immediately
        if len(self._clean_buf) >= n:
            data = bytes(self._clean_buf[:n])
            del self._clean_buf[:n]
            return data

        try:
            self._sock.settimeout(timeout)
            raw = self._sock.recv(self.BUFFER_SIZE)
            if not raw:
                raise MRVAuthError("Connection closed by remote host.")
            self._raw_buf.extend(raw)
            self._process_iac()
        except socket.timeout:
            pass   # return what we have (may be empty)
        except OSError as exc:
            raise MRVAuthError(f"Socket error: {exc}") from exc

        data = bytes(self._clean_buf[:n])
        del self._clean_buf[:n]
        return data

    def read_until(
        self,
        expected: bytes,
        timeout: float = 8.0,
        on_data: Optional[Callable[[bytes], None]] = None,
    ) -> bytes:
        """
        Read clean bytes until *expected* is found or *timeout* elapses.

        Args:
            expected: Byte sequence to wait for (searched in clean data).
            timeout:  Total seconds to wait.
            on_data:  Optional callback(bytes) fired on each clean chunk.

        Returns:
            All clean bytes accumulated up to and including *expected*.

        Raises:
            MRVAuthError: Timeout or socket closed before *expected* seen.
        """
        accumulated = bytearray()
        deadline = time.monotonic() + timeout

        while expected not in accumulated:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MRVAuthError(
                    f"Timeout ({timeout:.0f}s) waiting for {expected!r}.\n"
                    "Check: device IP, Telnet port, and credentials."
                )
            try:
                self._sock.settimeout(min(remaining, 1.0))
                raw = self._sock.recv(self.BUFFER_SIZE)
                if not raw:
                    raise MRVAuthError("Connection closed by remote host during auth.")
                self._raw_buf.extend(raw)
                self._process_iac()

                # Drain freshly cleaned bytes
                if self._clean_buf:
                    chunk = bytes(self._clean_buf)
                    self._clean_buf.clear()
                    accumulated.extend(chunk)
                    if on_data:
                        on_data(chunk)
            except socket.timeout:
                continue
            except OSError as exc:
                raise MRVAuthError(f"Socket error: {exc}") from exc

        return bytes(accumulated)

    def read_eager(self) -> bytes:
        """
        Non-blocking: return whatever clean data is already buffered plus
        any data immediately available on the socket (1-ms select).

        Returns:
            Clean bytes (may be empty).
        """
        # Peek with a very short timeout
        try:
            ready, _, _ = select.select([self._sock], [], [], 0.001)
            if ready:
                raw = self._sock.recv(self.BUFFER_SIZE)
                if raw:
                    self._raw_buf.extend(raw)
                    self._process_iac()
        except OSError:
            pass

        data = bytes(self._clean_buf)
        self._clean_buf.clear()
        return data

    # ── Private IAC parser ────────────────────────────────────────────────────
    def _process_iac(self) -> None:
        """
        Parse self._raw_buf in place:
        • IAC WILL X  → send IAC DONT X,  consume 3 bytes
        • IAC WONT X  → consume 3 bytes (no reply needed)
        • IAC DO   X  → send IAC WONT X,  consume 3 bytes
        • IAC DONT X  → consume 3 bytes (no reply needed)
        • IAC SB … SE → consume sub-negotiation block
        • IAC IAC     → emit literal 0xFF, consume 2 bytes
        • IAC <other> → consume 2 bytes silently
        • Non-IAC     → move to clean buffer
        """
        buf = self._raw_buf
        i = 0
        n = len(buf)

        while i < n:
            b = buf[i]

            if b != _IAC:
                # Plain data byte — pass through to clean buffer
                self._clean_buf.append(b)
                i += 1
                continue

            # Need at least 2 bytes for any IAC command
            if i + 1 >= n:
                break   # wait for more data

            cmd = buf[i + 1]

            if cmd == _IAC:
                # Escaped literal 0xFF
                self._clean_buf.append(_IAC)
                i += 2

            elif cmd in (_WILL, _WONT, _DO, _DONT):
                # Need 3 bytes: IAC CMD OPTION
                if i + 2 >= n:
                    break
                option = buf[i + 2]
                self._reply_negotiation(cmd, option)
                log.debug(
                    "IAC %s 0x%02x → replied",
                    {_WILL: "WILL", _WONT: "WONT", _DO: "DO", _DONT: "DONT"}.get(cmd, "?"),
                    option,
                )
                i += 3

            elif cmd == _SB:
                # Sub-negotiation: scan forward for IAC SE
                end = buf.find(bytes([_IAC, _SE]), i + 2)
                if end == -1:
                    break   # incomplete — wait for more
                i = end + 2

            else:
                # Unknown 2-byte sequence — skip
                i += 2

        # Remove consumed bytes from raw buffer
        del self._raw_buf[:i]

    def _reply_negotiation(self, cmd: int, option: int) -> None:
        """
        Send the appropriate RFC 854 refusal reply.

        Args:
            cmd:    The IAC command byte received (WILL/WONT/DO/DONT).
            option: The Telnet option byte.
        """
        match cmd:
            case _ if cmd == _WILL:
                reply = bytes([_IAC, _DONT, option])
            case _ if cmd == _DO:
                reply = bytes([_IAC, _WONT, option])
            case _:
                return   # WONT/DONT — no reply required
        try:
            self._sock.sendall(reply)
        except OSError as exc:
            log.warning("Failed to send IAC reply: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Backend — pure network / protocol layer (zero Tkinter imports)
# ─────────────────────────────────────────────────────────────────────────────
class MRVBackend:
    """
    Thread-safe Telnet client for the MRV LX-5250.

    Uses TelnetIACHandler (raw socket + manual RFC 854 negotiation) instead
    of the stdlib telnetlib which was removed in Python 3.13.

    State machine
    ─────────────
    IDLE  ──connect()──► CONNECTING ──auth ok──► READY
                                     └─auth fail─► IDLE
    READY ──disconnect()──► IDLE
    """

    PROMPT_USER: bytes = b"Username: "
    PROMPT_PASS: bytes = b"Password: "
    PROMPT_CMD:  bytes = b"LX: "       # also catches "LX: ?"
    AUTH_TIMEOUT: float = 10.0
    READ_TIMEOUT: float = 2.0
    CONNECT_TIMEOUT: float = 5.0

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._iac: Optional[TelnetIACHandler] = None
        self._lock = threading.Lock()
        self._connected = False
        self._authenticated = False
        log.debug("MRVBackend initialised.")

    # ── Public state ──────────────────────────────────────────────────────────
    @property
    def is_connected(self) -> bool:
        """True once the TCP socket is open."""
        return self._connected

    @property
    def is_authenticated(self) -> bool:
        """True once the device prompt 'LX: ' has been seen."""
        return self._authenticated

    # ── Connection lifecycle ──────────────────────────────────────────────────
    def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        on_data: Optional[Callable[[bytes], None]] = None,
    ) -> None:
        """
        Open the TCP connection, handle IAC negotiation, and authenticate.

        Args:
            host:      Device IP or hostname.
            port:      Telnet port (typically 23).
            username:  Login username (NOT logged).
            password:  Login password (NOT logged).
            on_data:   Callback(bytes) invoked with clean text chunks.

        Raises:
            MRVConnectionError: TCP connection failure.
            MRVAuthError:       Auth timeout or rejected credentials.
        """
        log.info("Connecting to %s:%d", host, port)
        try:
            sock = socket.create_connection((host, port), timeout=self.CONNECT_TIMEOUT)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            raise MRVConnectionError(f"Cannot reach {host}:{port} — {exc}") from exc

        iac = TelnetIACHandler(sock)

        with self._lock:
            self._sock = sock
            self._iac  = iac
            self._connected = True

        log.debug("TCP connected; TelnetIACHandler active; starting auth state machine.")
        self._run_auth(username, password, on_data)

    def disconnect(self) -> None:
        """Close socket and reset all state flags."""
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                    log.info("Socket closed by client.")
                except OSError:
                    pass
                self._sock = None
                self._iac  = None
            self._connected = False
            self._authenticated = False

    # ── Command send ──────────────────────────────────────────────────────────
    def send_command(self, command: str) -> None:
        """
        Send a validated command string to the device.

        Args:
            command: Command text WITHOUT trailing newline (appended here).

        Raises:
            MRVCommandError: Not authenticated or socket closed.
        """
        if not self._authenticated:
            raise MRVCommandError("Not authenticated — connect first.")
        with self._lock:
            iac = self._iac
        if iac is None:
            raise MRVCommandError("Telnet handler not initialised.")
        payload = (command.strip() + "\r\n").encode("ascii", errors="replace")
        iac.write(payload)
        log.debug("Sent command: %r", command.strip())

    # ── Continuous reader (runs in its own daemon thread) ─────────────────────
    def read_loop(
        self,
        on_data: Callable[[bytes], None],
        on_disconnect: Callable[[], None],
    ) -> None:
        """
        Blocking loop that reads clean data and fires on_data(bytes).
        Returns when disconnected; calls on_disconnect() before returning.

        Args:
            on_data:       Callback(bytes) for each clean chunk received.
            on_disconnect: Callback() on unexpected socket close.
        """
        log.debug("Read loop started (IAC-aware).")
        try:
            while self._connected:
                with self._lock:
                    iac = self._iac
                if iac is None:
                    break
                try:
                    chunk = iac.read(4096, timeout=self.READ_TIMEOUT)
                    if chunk:
                        on_data(chunk)
                except MRVAuthError as exc:
                    log.warning("Read loop: %s", exc)
                    break
                except OSError:
                    break
        finally:
            self.disconnect()
            on_disconnect()
            log.debug("Read loop exited.")

    # ── Private auth state machine ────────────────────────────────────────────
    def _run_auth(
        self,
        username: str,
        password: str,
        on_data: Optional[Callable[[bytes], None]],
    ) -> None:
        """
        Three-step Telnet authentication using TelnetIACHandler.read_until().
        IAC negotiation is transparently handled; only clean ASCII reaches here.

        Raises:
            MRVAuthError: On timeout or credential rejection.
        """
        with self._lock:
            iac = self._iac
        if iac is None:
            raise MRVAuthError("Socket not initialised.")

        try:
            log.debug("Waiting for 'Username: ' prompt (IAC negotiation in progress) …")
            iac.read_until(
                self.PROMPT_USER, timeout=self.AUTH_TIMEOUT, on_data=on_data
            )
            iac.write(username.encode("ascii", errors="ignore") + b"\r\n")
            log.debug("Username sent.")

            log.debug("Waiting for 'Password: ' prompt …")
            iac.read_until(
                self.PROMPT_PASS, timeout=self.AUTH_TIMEOUT, on_data=on_data
            )
            iac.write(password.encode("ascii", errors="ignore") + b"\r\n")
            log.debug("Password sent. [redacted from log]")

            log.debug("Waiting for command prompt 'LX: ' …")
            iac.read_until(
                self.PROMPT_CMD, timeout=self.AUTH_TIMEOUT, on_data=on_data
            )

        except MRVAuthError:
            self.disconnect()
            raise

        with self._lock:
            self._authenticated = True
        log.info("Authentication successful — 'LX: ' prompt seen.")


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────
def _lighten(hex_color: str, factor: float = 0.25) -> str:
    """
    Return a slightly lighter version of *hex_color* for hover effects.

    Args:
        hex_color: CSS hex string such as '#006622'.
        factor:    Lightening factor in [0, 1].

    Returns:
        Lightened hex color string.
    """
    hex_color = hex_color.lstrip("#")
    if len(hex_color) != 6:
        return f"#{hex_color}"
    r, g, b = (int(hex_color[i: i + 2], 16) for i in (0, 2, 4))
    r = min(255, int(r + (255 - r) * factor))
    g = min(255, int(g + (255 - g) * factor))
    b = min(255, int(b + (255 - b) * factor))
    return f"#{r:02x}{g:02x}{b:02x}"


# ─────────────────────────────────────────────────────────────────────────────
# GUI Application
# ─────────────────────────────────────────────────────────────────────────────
class MRVApp:
    """
    Main Tkinter application window for the MRV LX-5250 manager.

    Threading model
    ───────────────
    • Main thread:  Tkinter event loop only.
    • Worker threads: connect, disconnect, send — all daemon threads.
    • Reader thread: persistent read_loop after auth, daemon thread.
    • Queue: worker → main thread communication; drained by root.after() poll.
    """

    POLL_MS: int = 16          # ~60 Hz
    WIN_TITLE    = "MRV LX-5250  —  Console Server Manager"
    WIN_GEOMETRY = "760x640"
    TERM_BG      = "#0d0d0d"
    TERM_FG      = "#00ff41"   # Matrix green
    TERM_FONT    = ("Consolas", 10)

    # Colour palette
    C_BG_DARK   = "#1a1a2e"
    C_BG_PANEL  = "#16213e"
    C_ENTRY_BG  = "#0f3460"
    C_LABEL_FG  = "#c0cfe8"
    C_HEAD_FG   = "#a0c4ff"

    def __init__(self, root: tk.Tk) -> None:
        self._root = root
        self._backend = MRVBackend()
        self._ui_queue: queue.Queue[tuple] = queue.Queue()
        self._reader_thread: Optional[threading.Thread] = None

        self._setup_window()
        self._build_security_banner()
        self._build_login_frame()
        self._build_controls_frame()
        self._build_terminal_frame()
        self._build_status_bar()

        # Kick off the perpetual UI-queue drain loop
        self._root.after(self.POLL_MS, self._poll_ui_queue)
        log.debug("GUI initialised.")

    # ── Window ────────────────────────────────────────────────────────────────
    def _setup_window(self) -> None:
        self._root.title(self.WIN_TITLE)
        self._root.geometry(self.WIN_GEOMETRY)
        self._root.resizable(True, True)
        self._root.configure(bg=self.C_BG_DARK)
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Security banner ───────────────────────────────────────────────────────
    def _build_security_banner(self) -> None:
        tk.Label(
            self._root,
            text="⚠  WARNING: Cleartext Telnet in use. Use SSH in production.  ⚠",
            fg="#ff4444",
            bg="#2a0000",
            font=("Consolas", 9, "bold"),
            pady=5,
            anchor="center",
        ).pack(fill="x", side="top")

    # ── Frame 1 — Login ───────────────────────────────────────────────────────
    def _build_login_frame(self) -> None:
        outer = tk.LabelFrame(
            self._root,
            text=" Connection",
            fg=self.C_HEAD_FG,
            bg=self.C_BG_PANEL,
            font=("Segoe UI", 9, "bold"),
            bd=2,
            relief="groove",
            padx=10,
            pady=6,
        )
        outer.pack(fill="x", padx=10, pady=(6, 2))

        def lbl(parent: tk.Widget, text: str) -> tk.Label:
            return tk.Label(
                parent, text=text,
                fg=self.C_LABEL_FG, bg=self.C_BG_PANEL,
                font=("Segoe UI", 9), anchor="w",
            )

        def ent(parent: tk.Widget, **kw) -> tk.Entry:
            return tk.Entry(
                parent,
                bg=self.C_ENTRY_BG, fg="#e0e0e0",
                insertbackground="white", relief="flat",
                font=("Consolas", 10), **kw,
            )

        # Row 0 — IP & Port
        row0 = tk.Frame(outer, bg=self.C_BG_PANEL)
        row0.pack(fill="x", pady=2)
        lbl(row0, "Device IP:").grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._var_ip = tk.StringVar(value="192.168.1.252")
        ent(row0, textvariable=self._var_ip, width=18).grid(row=0, column=1, sticky="w")
        lbl(row0, "  Port:").grid(row=0, column=2, sticky="w", padx=(12, 4))
        self._var_port = tk.StringVar(value="23")
        ent(row0, textvariable=self._var_port, width=6).grid(row=0, column=3, sticky="w")

        # Row 1 — Username & Password
        row1 = tk.Frame(outer, bg=self.C_BG_PANEL)
        row1.pack(fill="x", pady=2)
        lbl(row1, "Username:").grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._var_user = tk.StringVar(value="Admn")
        ent(row1, textvariable=self._var_user, width=18).grid(row=0, column=1, sticky="w")
        lbl(row1, "  Password:").grid(row=0, column=2, sticky="w", padx=(12, 4))
        self._var_pass = tk.StringVar()
        ent(row1, textvariable=self._var_pass, show="*", width=18).grid(
            row=0, column=3, sticky="w"
        )

        # Buttons
        btn_row = tk.Frame(outer, bg=self.C_BG_PANEL)
        btn_row.pack(fill="x", pady=(8, 2))

        self._btn_connect = self._make_button(
            btn_row, "⚡  Connect", "#0055aa", self._on_connect, width=14
        )
        self._btn_connect.pack(side="left", padx=(0, 8))

        self._btn_disconnect = self._make_button(
            btn_row, "✖  Disconnect", "#880000", self._on_disconnect, width=14
        )
        self._btn_disconnect.pack(side="left")
        self._btn_disconnect.config(state="disabled")

    # ── Frame 2 — Port Controls ───────────────────────────────────────────────
    def _build_controls_frame(self) -> None:
        outer = tk.LabelFrame(
            self._root,
            text=" Port Control  &  System Commands",
            fg=self.C_HEAD_FG,
            bg=self.C_BG_PANEL,
            font=("Segoe UI", 9, "bold"),
            bd=2,
            relief="groove",
            padx=10,
            pady=6,
        )
        outer.pack(fill="x", padx=10, pady=2)
        self._ctrl_frame = outer

        # Port ID entry with validatecommand
        pid_row = tk.Frame(outer, bg=self.C_BG_PANEL)
        pid_row.pack(fill="x", pady=(0, 4))

        tk.Label(
            pid_row,
            text="Port ID (1-8):",
            fg=self.C_LABEL_FG, bg=self.C_BG_PANEL,
            font=("Segoe UI", 9),
        ).pack(side="left", padx=(0, 6))

        vcmd = (self._root.register(self._validate_port_id), "%P")
        self._var_port_id = tk.StringVar()
        self._ent_port_id = tk.Entry(
            pid_row,
            textvariable=self._var_port_id,
            validate="key",
            validatecommand=vcmd,
            width=4,
            bg=self.C_ENTRY_BG,
            fg="#e0e0e0",
            insertbackground="white",
            relief="flat",
            font=("Consolas", 11, "bold"),
        )
        self._ent_port_id.pack(side="left")

        # Port-action buttons: ON / OFF / CONNECT
        port_btn_row = tk.Frame(outer, bg=self.C_BG_PANEL)
        port_btn_row.pack(fill="x", pady=(0, 4))

        port_cmds: list[tuple[str, str, str]] = [
            ("  ON  ", "#006622", "ON"),
            ("  OFF  ", "#880000", "OFF"),
            ("CONNECT", "#004488", "CONNECT"),
        ]
        self._port_buttons: list[tk.Button] = []
        for label, color, cmd in port_cmds:
            btn = self._make_button(
                port_btn_row, label, color,
                lambda c=cmd: self._on_port_command(c),
                width=10,
            )
            btn.pack(side="left", padx=4)
            self._port_buttons.append(btn)

        # Separator
        ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=4)

        # System-command buttons: STATUS / ISTAT / ENVMON / LIST
        tk.Label(
            outer,
            text="System Commands:",
            fg="#8899bb", bg=self.C_BG_PANEL,
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        sys_btn_row = tk.Frame(outer, bg=self.C_BG_PANEL)
        sys_btn_row.pack(fill="x", pady=(2, 0))

        sys_cmds: list[str] = ["STATUS", "ISTAT", "ENVMON", "LIST"]
        self._sys_buttons: list[tk.Button] = []
        for cmd in sys_cmds:
            btn = self._make_button(
                sys_btn_row, cmd, "#334466",
                lambda c=cmd: self._on_sys_command(c),
                width=10,
            )
            btn.pack(side="left", padx=4)
            self._sys_buttons.append(btn)

        # Start locked
        self._set_controls_state("disabled")

    # ── Frame 3 — Terminal ────────────────────────────────────────────────────
    def _build_terminal_frame(self) -> None:
        outer = tk.LabelFrame(
            self._root,
            text=" Device Terminal Output",
            fg=self.C_HEAD_FG,
            bg=self.C_BG_PANEL,
            font=("Segoe UI", 9, "bold"),
            bd=2,
            relief="groove",
            padx=6,
            pady=6,
        )
        outer.pack(fill="both", expand=True, padx=10, pady=(2, 4))

        self._terminal = scrolledtext.ScrolledText(
            outer,
            bg=self.TERM_BG,
            fg=self.TERM_FG,
            insertbackground=self.TERM_FG,
            font=self.TERM_FONT,
            relief="flat",
            state="disabled",
            wrap="word",
        )
        self._terminal.pack(fill="both", expand=True)

        # Colour tags for annotated messages
        self._terminal.tag_config("error", foreground="#ff6666")
        self._terminal.tag_config("info",  foreground="#88ddff")
        self._terminal.tag_config("warn",  foreground="#ffcc44")

    # ── Status bar ────────────────────────────────────────────────────────────
    def _build_status_bar(self) -> None:
        bar = tk.Frame(self._root, bg="#0d0d0d", height=22)
        bar.pack(fill="x", side="bottom")

        self._lbl_status = tk.Label(
            bar,
            text="●  Disconnected",
            fg="#ff4444", bg="#0d0d0d",
            font=("Segoe UI", 9),
            anchor="w", padx=8,
        )
        self._lbl_status.pack(side="left", fill="y")

    # ── Button factory ────────────────────────────────────────────────────────
    @staticmethod
    def _make_button(
        parent: tk.Widget,
        text: str,
        color: str,
        command: Callable,
        width: int = 12,
    ) -> tk.Button:
        """
        Create a styled flat button with hover animation.

        Args:
            parent:  Parent widget.
            text:    Button label.
            color:   Background hex colour (e.g. '#006622').
            command: Click callback.
            width:   Button character width.

        Returns:
            Configured tk.Button.
        """
        btn = tk.Button(
            parent,
            text=text,
            bg=color, fg="white",
            activebackground="#ffffff", activeforeground="#000000",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            width=width,
            cursor="hand2",
            command=command,
        )

        def _enter(e: tk.Event, b: tk.Button = btn, c: str = color) -> None:  # noqa: E731
            b.config(bg=_lighten(c))

        def _leave(e: tk.Event, b: tk.Button = btn, c: str = color) -> None:  # noqa: E731
            b.config(bg=c)

        btn.bind("<Enter>", _enter)
        btn.bind("<Leave>", _leave)
        return btn

    # ── Input validation ──────────────────────────────────────────────────────
    @staticmethod
    def _validate_port_id(proposed: str) -> bool:
        """
        Tkinter validatecommand for the Port ID entry.
        Allows only empty string or a single digit 1-8.

        Args:
            proposed: Current proposed entry content.

        Returns:
            True if acceptable, False to reject the keystroke.
        """
        if proposed == "":
            return True
        if len(proposed) > 1:
            return False
        return proposed.isdigit() and 1 <= int(proposed) <= 8

    def _get_validated_port_id(self) -> Optional[int]:
        """
        Return integer Port ID from the entry, or None on validation failure.

        Returns:
            int in [1, 8] or None; writes error to terminal on failure.
        """
        raw = self._var_port_id.get().strip()
        if not raw:
            self._term_write("[INPUT ERROR] Port ID is empty — enter a value 1-8.\n", "error")
            return None
        if not raw.isdigit() or not (1 <= int(raw) <= 8):
            self._term_write(
                f"[INPUT ERROR] '{raw}' rejected — only integers 1-8 allowed "
                "(command injection prevention).\n",
                "error",
            )
            log.warning("Blocked invalid Port ID input: %r", raw)
            return None
        return int(raw)

    # ── Event handlers (main thread) ──────────────────────────────────────────
    def _on_connect(self) -> None:
        """Validate connection fields, then dispatch connect worker thread."""
        host     = self._var_ip.get().strip()
        port_str = self._var_port.get().strip()
        username = self._var_user.get().strip()
        password = self._var_pass.get()   # NOT stripped — passwords may have spaces

        if not host:
            messagebox.showwarning("Missing Input", "Device IP cannot be empty.")
            return
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            messagebox.showwarning("Invalid Port", "TCP port must be an integer 1-65535.")
            return
        if not username:
            messagebox.showwarning("Missing Input", "Username cannot be empty.")
            return

        self._term_write(
            f"[INFO] Connecting to {host}:{port_str} as '{username}' …\n", "info"
        )
        self._set_status("Connecting …", "#ffcc44")
        self._btn_connect.config(state="disabled")
        self._btn_disconnect.config(state="normal")

        threading.Thread(
            target=self._worker_connect,
            args=(host, int(port_str), username, password),
            daemon=True,
            name="mrv-connect",
        ).start()

    def _on_disconnect(self) -> None:
        """Dispatch disconnect worker thread."""
        threading.Thread(
            target=self._worker_disconnect,
            daemon=True,
            name="mrv-disconnect",
        ).start()

    def _on_port_command(self, cmd: str) -> None:
        """
        Validate Port ID then send '<CMD> <PORT_ID>' on a worker thread.

        Args:
            cmd: 'ON', 'OFF', or 'CONNECT'.
        """
        port_id = self._get_validated_port_id()
        if port_id is None:
            return

        # Confirmation gate for destructive OFF command
        if cmd == "OFF":
            if not messagebox.askyesno(
                "Confirm Power OFF",
                f"Cut power to Port {port_id}?\n\n"
                "This will immediately remove power from the connected device.",
                icon="warning",
            ):
                self._term_write("[CANCELLED] OFF command aborted by operator.\n", "warn")
                return

        full_cmd = f"{cmd} {port_id}"
        threading.Thread(
            target=self._worker_send,
            args=(full_cmd,),
            daemon=True,
            name=f"mrv-cmd-{cmd}",
        ).start()

    def _on_sys_command(self, cmd: str) -> None:
        """Send a system command that requires no Port ID."""
        threading.Thread(
            target=self._worker_send,
            args=(cmd,),
            daemon=True,
            name=f"mrv-sys-{cmd}",
        ).start()

    def _on_close(self) -> None:
        """Gracefully disconnect and destroy window."""
        log.info("Application window closing.")
        self._backend.disconnect()
        self._root.destroy()

    # ── Worker threads (daemon; NOT on main thread) ───────────────────────────
    def _worker_connect(
        self, host: str, port: int, username: str, password: str
    ) -> None:
        """Run authentication state machine; start reader loop on success."""
        try:
            self._backend.connect(
                host=host,
                port=port,
                username=username,
                password=password,
                on_data=self._enqueue_raw,
            )
        except MRVConnectionError as exc:
            self._enqueue_write(f"[CONN ERROR] {exc}\n", "error")
            self._enqueue_call(self._reset_ui_disconnected)
            return
        except MRVAuthError as exc:
            self._enqueue_write(f"[AUTH ERROR] {exc}\n", "error")
            self._enqueue_call(self._reset_ui_disconnected)
            return
        except Exception as exc:  # noqa: BLE001
            self._enqueue_write(f"[UNEXPECTED] {exc}\n", "error")
            self._enqueue_call(self._reset_ui_disconnected)
            log.exception("Unexpected error in connect worker.")
            return

        # Authentication succeeded
        self._enqueue_write("\n[INFO] ✓ Login successful — Port Controls unlocked.\n", "info")
        self._enqueue_call(self._on_auth_success)

        # Launch persistent read loop
        self._reader_thread = threading.Thread(
            target=self._backend.read_loop,
            kwargs={
                "on_data": self._enqueue_raw,
                "on_disconnect": lambda: self._enqueue_call(self._reset_ui_disconnected),
            },
            daemon=True,
            name="mrv-reader",
        )
        self._reader_thread.start()

    def _worker_disconnect(self) -> None:
        self._backend.disconnect()
        self._enqueue_write("\n[INFO] Disconnected by operator.\n", "info")
        self._enqueue_call(self._reset_ui_disconnected)

    def _worker_send(self, cmd: str) -> None:
        try:
            self._enqueue_write(f"\n[CMD] > {cmd}\n", "info")
            self._backend.send_command(cmd)
        except MRVCommandError as exc:
            self._enqueue_write(f"[CMD ERROR] {exc}\n", "error")

    # ── Queue / UI-update bridge ──────────────────────────────────────────────
    def _enqueue_raw(self, data: bytes) -> None:
        """Decode raw device bytes and push to UI queue (called from worker thread)."""
        text = data.decode("ascii", errors="replace")
        self._ui_queue.put(("write", text, None))

    def _enqueue_write(self, text: str, tag: Optional[str] = None) -> None:
        self._ui_queue.put(("write", text, tag))

    def _enqueue_call(self, fn: Callable) -> None:
        self._ui_queue.put(("call", fn, None))

    def _poll_ui_queue(self) -> None:
        """
        Drain up to 100 queued UI messages per tick (main thread only).
        Reschedules itself indefinitely via root.after().
        """
        for _ in range(100):
            try:
                kind, payload, tag = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            if kind == "write":
                self._term_write(payload, tag)
            elif kind == "call":
                payload()

        self._root.after(self.POLL_MS, self._poll_ui_queue)

    # ── Terminal write (MUST be called on main thread) ────────────────────────
    def _term_write(self, text: str, tag: Optional[str] = None) -> None:
        """
        Append text to the read-only terminal widget.

        Args:
            text: Text to append.
            tag:  Optional colour tag ('error', 'info', 'warn').
        """
        self._terminal.config(state="normal")
        if tag:
            self._terminal.insert("end", text, tag)
        else:
            self._terminal.insert("end", text)
        self._terminal.see("end")
        self._terminal.config(state="disabled")

    # ── UI state helpers (main thread) ────────────────────────────────────────
    def _set_controls_state(self, state: str) -> None:
        """Enable or disable all controls in Frame 2."""
        for btn in self._port_buttons + self._sys_buttons:
            btn.config(state=state)
        self._ent_port_id.config(state=state)

    def _set_status(self, text: str, color: str) -> None:
        self._lbl_status.config(text=f"●  {text}", fg=color)

    def _on_auth_success(self) -> None:
        self._set_controls_state("normal")
        self._set_status("Connected & Authenticated", "#44ff88")

    def _reset_ui_disconnected(self) -> None:
        self._set_controls_state("disabled")
        self._btn_connect.config(state="normal")
        self._btn_disconnect.config(state="disabled")
        self._set_status("Disconnected", "#ff4444")


# ─────────────────────────────────────────────────────────────────────────────
# Entry-point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    """Launch the MRV LX-5250 management GUI."""
    root = tk.Tk()
    _app = MRVApp(root)   # keeps reference alive for the duration of the loop
    root.mainloop()


if __name__ == "__main__":
    main()
