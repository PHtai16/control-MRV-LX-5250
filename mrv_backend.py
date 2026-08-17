# -*- coding: utf-8 -*-
"""
mrv_backend.py
─────────────────────────────────────────────────────────────────────────────
Network backend  —  MRV LX-5250 Console Server / Switched PDU (Firmware 5.3f)
Author : Senior Software Engineer / Blue Team Security
Python : 3.10+  |  stdlib only (socket, threading, logging)

NOTE ON telnetlib
─────────────────
telnetlib was deprecated in Python 3.11 and REMOVED in Python 3.13+.
This module implements RFC 854 Telnet IAC negotiation directly over a raw
TCP socket.  The _TelnetIAC class provides the same semantics as
telnetlib.Telnet but is fully compatible with Python 3.13+.

Key improvement — root-cause fix for 5-minute auth timeout
──────────────────────────────────────────────────────────
read_until_any() waits for *any* of several candidate prompts.  This handles
devices that send "Password: ", "password: ", or "Passwd: " and is also the
reason the original single-socket implementation timed out: the password
prompt arrived mixed with new IAC negotiations that were never stripped.
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from enum import Enum, auto
from typing import Callable, Optional

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# RFC 854 — Telnet command byte constants
# ─────────────────────────────────────────────────────────────────────────────
_IAC  = 0xFF   # 255  Interpret As Command
_WILL = 0xFB   # 251  I will use option
_WONT = 0xFC   # 252  I will not use option
_DO   = 0xFD   # 253  Please do option
_DONT = 0xFE   # 254  Do not use option
_SB   = 0xFA   # 250  Sub-negotiation begin
_SE   = 0xF0   # 240  Sub-negotiation end


# ─────────────────────────────────────────────────────────────────────────────
# Custom exceptions
# ─────────────────────────────────────────────────────────────────────────────
class MRVError(Exception):
    """Base class for all MRV backend exceptions."""


class MRVConnectionError(MRVError):
    """TCP connection could not be established or was lost unexpectedly."""


class MRVAuthError(MRVError):
    """Authentication failed (timeout, bad credentials, or unexpected prompt)."""


class MRVCommandError(MRVError):
    """A command could not be sent (not authenticated or socket closed)."""


# ─────────────────────────────────────────────────────────────────────────────
# RFC 854 Telnet IAC handler  (drop-in replacement for removed telnetlib)
# ─────────────────────────────────────────────────────────────────────────────
class _TelnetIAC:
    """
    Wraps a raw TCP socket and transparently handles Telnet IAC negotiation.

    Negotiation policy: NVT-minimal, sufficient for PDU/console sessions.
      IAC WILL X  ->  send IAC DONT X   (decline all server-offered options)
      IAC DO   X  ->  send IAC WONT X   (decline all server-demanded options)
      IAC WONT X  ->  no reply          (acknowledge decline)
      IAC DONT X  ->  no reply          (acknowledge decline)
      IAC SB...SE ->  consume silently  (skip sub-negotiation block)
      IAC IAC     ->  emit literal 0xFF to clean stream

    NOT internally thread-safe; callers must serialize access (MRVBackend._lock).
    """

    _RECV_SIZE = 4096

    def __init__(self, sock: socket.socket) -> None:
        self._sock:    socket.socket = sock
        self._clean:   bytearray    = bytearray()
        self._pending: bytearray    = bytearray()

    # ── Outbound ──────────────────────────────────────────────────────────────
    def write(self, data: bytes) -> None:
        """
        Send bytes to device, escaping 0xFF -> 0xFF 0xFF per RFC 854.

        Args:
            data: Raw bytes to transmit.

        Raises:
            MRVCommandError: If sendall() fails.
        """
        escaped = data.replace(bytes([_IAC]), bytes([_IAC, _IAC]))
        try:
            self._sock.sendall(escaped)
        except OSError as exc:
            raise MRVCommandError(f"Write failed: {exc}") from exc

    # ── Inbound ───────────────────────────────────────────────────────────────
    def read(self, timeout: float = 2.0) -> bytes:
        """
        Return available clean (IAC-stripped) bytes. May return b'' on timeout.

        Args:
            timeout: Per-recv timeout in seconds.

        Returns:
            Clean bytes; empty if nothing arrived within timeout.

        Raises:
            MRVConnectionError: If socket closes unexpectedly.
        """
        if self._clean:
            out = bytes(self._clean)
            self._clean.clear()
            return out
        try:
            self._sock.settimeout(timeout)
            raw = self._sock.recv(self._RECV_SIZE)
        except socket.timeout:
            return b""
        except OSError as exc:
            raise MRVConnectionError(f"recv error: {exc}") from exc

        if not raw:
            raise MRVConnectionError("Remote host closed the connection.")

        self._pending.extend(raw)
        self._parse_iac()

        out = bytes(self._clean)
        self._clean.clear()
        return out

    def read_until(
        self,
        match: bytes,
        timeout: float,
        on_data: Optional[Callable[[bytes], None]] = None,
    ) -> bytes:
        """
        Block until `match` appears in the clean stream, or raise on timeout.

        Args:
            match:   Byte sequence to search for.
            timeout: Maximum seconds to wait.
            on_data: Optional callback fired with each clean chunk received.

        Returns:
            All accumulated clean bytes.

        Raises:
            MRVAuthError: On timeout or unexpected close.
        """
        _, accumulated = self._read_until_any([match], timeout, on_data)
        return accumulated

    def read_until_any(
        self,
        candidates: list[bytes],
        timeout: float,
        on_data: Optional[Callable[[bytes], None]] = None,
    ) -> tuple[bytes, bytes]:
        """
        Block until any of `candidates` appears in the clean stream.

        Preferred for auth flows because it handles variant prompt strings
        (e.g. "Password: " vs "password: " vs "Passwd: ").

        Args:
            candidates: Ordered list of byte sequences to wait for.
            timeout:    Maximum seconds to wait.
            on_data:    Optional per-chunk callback.

        Returns:
            (matched_candidate, all_accumulated_clean_bytes).

        Raises:
            MRVAuthError: On timeout or unexpected close.
        """
        return self._read_until_any(candidates, timeout, on_data)

    # ── Private helpers ───────────────────────────────────────────────────────
    def _read_until_any(
        self,
        candidates: list[bytes],
        timeout: float,
        on_data: Optional[Callable[[bytes], None]],
    ) -> tuple[bytes, bytes]:
        """Core blocking read loop shared by read_until() and read_until_any()."""
        accumulated = bytearray()
        deadline    = time.monotonic() + timeout

        while True:
            for cand in candidates:
                if cand in accumulated:
                    return cand, bytes(accumulated)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                preview   = bytes(accumulated[-300:]).decode("ascii", errors="replace")
                cand_strs = [c.decode("ascii", errors="replace") for c in candidates]
                raise MRVAuthError(
                    f"Timeout ({timeout:.0f}s) waiting for one of {cand_strs}.\n"
                    f"Last {min(len(accumulated), 300)} clean bytes: {preview!r}\n"
                    "Check: device IP, Telnet port, credentials."
                )
            try:
                self._sock.settimeout(min(remaining, 0.5))
                raw = self._sock.recv(self._RECV_SIZE)
            except socket.timeout:
                continue
            except OSError as exc:
                raise MRVAuthError(f"Socket error during read: {exc}") from exc

            if not raw:
                raise MRVAuthError("Remote host closed connection during authentication.")

            self._pending.extend(raw)
            self._parse_iac()

            if self._clean:
                chunk = bytes(self._clean)
                self._clean.clear()
                accumulated.extend(chunk)
                if on_data:
                    on_data(chunk)

    def _parse_iac(self) -> None:
        """
        Scan self._pending in-place; separate IAC commands from plain data.

        Plain bytes   -> self._clean
        IAC WILL/DO   -> send DONT/WONT reply, consume 3 bytes
        IAC WONT/DONT -> no reply, consume 3 bytes
        IAC SB...SE   -> consume silently
        IAC IAC       -> emit one 0xFF to clean stream
        Unknown 2-byte-> skip silently
        Incomplete seq-> leave in _pending for next recv()
        """
        buf = self._pending
        i   = 0
        n   = len(buf)

        while i < n:
            b = buf[i]

            if b != _IAC:
                self._clean.append(b)
                i += 1
                continue

            if i + 1 >= n:
                break  # incomplete — wait for next recv

            cmd = buf[i + 1]

            if cmd == _IAC:
                self._clean.append(_IAC)
                i += 2

            elif cmd in (_WILL, _WONT, _DO, _DONT):
                if i + 2 >= n:
                    break  # option byte not yet received
                option = buf[i + 2]
                self._reply(cmd, option)
                i += 3

            elif cmd == _SB:
                iac_se = bytes([_IAC, _SE])
                end = buf.find(iac_se, i + 2)
                if end == -1:
                    break  # sub-negotiation incomplete
                i = end + 2

            else:
                i += 2  # unknown 2-byte sequence

        del self._pending[:i]

    def _reply(self, cmd: int, option: int) -> None:
        """
        Send the appropriate RFC 854 refusal reply for received IAC CMD.

        Args:
            cmd:    IAC command received (WILL/WONT/DO/DONT).
            option: Telnet option byte.
        """
        match cmd:
            case _ if cmd == _WILL:
                payload = bytes([_IAC, _DONT, option])
                log.debug("Telnet: WILL 0x%02x  ->  DONT", option)
            case _ if cmd == _DO:
                payload = bytes([_IAC, _WONT, option])
                log.debug("Telnet: DO   0x%02x  ->  WONT", option)
            case _:
                log.debug(
                    "Telnet: %s 0x%02x  (no reply)",
                    "WONT" if cmd == _WONT else "DONT",
                    option,
                )
                return
        try:
            self._sock.sendall(payload)
        except OSError as exc:
            log.warning("IAC reply failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Internal connection state machine
# ─────────────────────────────────────────────────────────────────────────────
class _ConnState(Enum):
    IDLE          = auto()
    CONNECTING    = auto()
    AUTHENTICATED = auto()


# ─────────────────────────────────────────────────────────────────────────────
# Public backend
# ─────────────────────────────────────────────────────────────────────────────
class MRVBackend:
    """
    Thread-safe Telnet client for the MRV LX-5250 (Firmware 5.3f).

    Threading contract
    ──────────────────
    connect()   MUST be called from a worker thread — it blocks until auth.
    read_loop() MUST be called from a second daemon thread after connect().
    on_data / on_disconnect callbacks fire from worker threads; GUI callers
    MUST marshal them to the main thread via queue + root.after().

    State machine
    ─────────────
    IDLE -> (connect) -> CONNECTING -> (auth ok) -> AUTHENTICATED
                                    -> (auth fail) -> IDLE
    AUTHENTICATED -> (disconnect/error) -> IDLE
    """

    _PROMPT_USER = b"Username: "
    _PROMPT_PASS = [b"Password: ", b"password: ", b"Passwd: "]
    _PROMPT_CMD  = b"LX: "

    CONNECT_TIMEOUT: float = 5.0
    AUTH_TIMEOUT:    float = 12.0
    READ_TIMEOUT:    float = 2.0

    def __init__(self) -> None:
        self._sock:  Optional[socket.socket] = None
        self._iac:   Optional[_TelnetIAC]    = None
        self._lock   = threading.Lock()
        self._state  = _ConnState.IDLE
        log.debug("MRVBackend initialised.")

    # ── Properties ────────────────────────────────────────────────────────────
    @property
    def is_connected(self) -> bool:
        """True when a TCP socket is open."""
        return self._state != _ConnState.IDLE

    @property
    def is_authenticated(self) -> bool:
        """True only after the LX: command prompt has been received."""
        return self._state == _ConnState.AUTHENTICATED

    # ── Connection lifecycle ──────────────────────────────────────────────────
    def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        on_data: Callable[[bytes], None],
    ) -> None:
        """
        Establish TCP connection and authenticate. BLOCKING — use worker thread.

        Args:
            host:      Device IP or hostname.
            port:      Telnet port (default 23).
            username:  Login name (not logged).
            password:  Login password (not logged).
            on_data:   Callback(bytes) for each clean received chunk.

        Raises:
            MRVConnectionError: TCP-level failure.
            MRVAuthError:       Auth timeout or refusal.
        """
        log.info("Connecting -> %s:%d", host, port)
        try:
            sock = socket.create_connection((host, port), timeout=self.CONNECT_TIMEOUT)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError as exc:
            raise MRVConnectionError(f"Cannot connect to {host}:{port}: {exc}") from exc

        iac = _TelnetIAC(sock)
        with self._lock:
            self._sock  = sock
            self._iac   = iac
            self._state = _ConnState.CONNECTING

        log.debug("TCP established. Starting IAC-aware auth.")
        self._authenticate(iac, username, password, on_data)

    def disconnect(self) -> None:
        """Close socket and reset to IDLE. Thread-safe; idempotent."""
        with self._lock:
            sock        = self._sock
            self._sock  = None
            self._iac   = None
            self._state = _ConnState.IDLE
        if sock:
            try:
                sock.close()
            except OSError:
                pass
            log.info("Disconnected.")

    def send_command(self, command: str) -> None:
        """
        Send a command string (CRLF appended automatically).

        Args:
            command: Command text without trailing newline.

        Raises:
            MRVCommandError: Not authenticated or socket gone.
        """
        if not self.is_authenticated:
            raise MRVCommandError("Not authenticated.")
        with self._lock:
            iac = self._iac
        if iac is None:
            raise MRVCommandError("No active connection.")
        payload = (command.rstrip() + "\r\n").encode("ascii", errors="replace")
        iac.write(payload)
        log.debug("CMD -> %r", command.strip())

    def read_loop(
        self,
        on_data: Callable[[bytes], None],
        on_disconnect: Callable[[], None],
    ) -> None:
        """
        Blocking read loop. MUST run from a daemon thread after connect().

        Args:
            on_data:       Callback(bytes) per clean chunk received.
            on_disconnect: Callback() fired once when connection drops.
        """
        log.debug("Read loop started.")
        try:
            while self.is_connected:
                with self._lock:
                    iac = self._iac
                if iac is None:
                    break
                try:
                    chunk = iac.read(timeout=self.READ_TIMEOUT)
                    if chunk:
                        on_data(chunk)
                except (MRVConnectionError, OSError) as exc:
                    log.warning("Read loop terminated: %s", exc)
                    break
        finally:
            self.disconnect()
            on_disconnect()
            log.debug("Read loop exited.")

    # ── Private auth ──────────────────────────────────────────────────────────
    def _authenticate(
        self,
        iac: _TelnetIAC,
        username: str,
        password: str,
        on_data: Callable[[bytes], None],
    ) -> None:
        """
        Three-step auth: Username prompt -> Password prompt -> LX: prompt.

        read_until_any() on the password step handles mixed-case variants and
        also detects if the device skips the password prompt entirely.

        Raises:
            MRVAuthError: On any failure; disconnects before re-raising.
        """
        try:
            log.debug("Awaiting 'Username: ' ...")
            iac.read_until(self._PROMPT_USER, self.AUTH_TIMEOUT, on_data)
            iac.write(username.encode("ascii", errors="ignore") + b"\r\n")
            log.debug("Username sent.")

            log.debug("Awaiting password or command prompt ...")
            pass_candidates: list[bytes] = self._PROMPT_PASS + [self._PROMPT_CMD]
            matched, _ = iac.read_until_any(pass_candidates, self.AUTH_TIMEOUT, on_data)

            if matched == self._PROMPT_CMD:
                log.info("Device granted access without password prompt.")
            else:
                iac.write(password.encode("ascii", errors="ignore") + b"\r\n")
                log.debug("Password sent.  [REDACTED FROM LOG]")

                log.debug("Awaiting 'LX: ' command prompt ...")
                iac.read_until(self._PROMPT_CMD, self.AUTH_TIMEOUT, on_data)

        except MRVAuthError:
            self.disconnect()
            raise

        with self._lock:
            self._state = _ConnState.AUTHENTICATED
        log.info("Authenticated — LX: prompt received.")
