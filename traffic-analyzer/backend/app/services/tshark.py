"""TShark adapter and live capture helpers.

OWNER: CaptureBridge.

This module is the only place in the backend that talks to the Wireshark
toolchain.  It offers two layers:

* a small, typed adapter class (:class:`TSharkAdapter`) that knows how to run
  the binary, parse its structured output and classify its failures, and
* the frozen module level functions (:func:`is_available`, :func:`tshark_version`,
  :func:`dissect_file`, :func:`list_interfaces`) that the rest of the
  application uses.

Design rules
------------
* Every TShark invocation uses an argument list - never ``shell=True``.
* Every invocation is bounded by a timeout (``config.TSHARK_TIMEOUT_SECONDS``).
* The return code and ``stderr`` of every command are inspected.  Human
  readable summaries are never parsed when structured output is available.
* A missing binary is reported, never silently ignored.
* All errors derive from :class:`TSharkUnavailable` so that a caller can catch
  a single type.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from .. import config

__all__ = [
    "DISSECT_FIELDS",
    "TSharkAdapter",
    "TSharkCommandError",
    "TSharkError",
    "TSharkNotFoundError",
    "TSharkOutputError",
    "TSharkPermissionError",
    "TSharkTimeoutError",
    "TSharkUnavailable",
    "count_packets",
    "dissect_file",
    "is_available",
    "list_interfaces",
    "tshark_version",
]

LOGGER = logging.getLogger(__name__)

#: TShark's field separator: ``/t`` is the TShark escape for a tab.
#:
#: TShark escapes control characters inside string fields (a tab inside a URI
#: is printed as ``\t``), so a raw tab can never appear inside a value and is
#: safe as a separator.  Quoting is disabled on purpose: TShark does not
#: escape embedded double quotes, so quoted output cannot be parsed
#: unambiguously.
FIELD_SEPARATOR = "/t"

#: The fields requested for every dissected frame.
#:
#: The list is the contract between this module and
#: ``app.services.normalize.normalize_tshark_rows`` - the row keys are the
#: TShark field names.  All of them exist in Wireshark 4.x.
DISSECT_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.len",
    "ipv6.plen",
    "tcp.flags",
    "tcp.stream",
    "http.request.method",
    "http.response.code",
    "http.host",
    "tls.record.version",
    "tls.handshake.extensions_server_name",
    "_ws.col.Protocol",
    "_ws.col.Info",
)

_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_VERSION_RE = re.compile(r"(?P<number>\d+\.\d+(?:\.\d+)?)")
_INTERFACE_RE = re.compile(r"^\s*(?P<index>\d+)\.\s*(?P<rest>.+?)\s*$")
_INTERFACE_FRIENDLY_RE = re.compile(r"^(?P<name>.*?)\s*\((?P<friendly>[^()]*)\)\s*$")

_PERMISSION_MARKERS = (
    "you don't have permission",
    "you do not have permission",
    "permission denied",
    "operation not permitted",
    "must be root",
    "requires root",
    "cap_net_raw",
    "cap_net_admin",
    "permission to capture",
)


class TSharkUnavailable(RuntimeError):
    """Base class for every TShark failure.

    The ingestion pipeline catches this single type, so every concrete error
    below derives from it.
    """


class TSharkNotFoundError(TSharkUnavailable):
    """The TShark binary or the capture file to dissect does not exist."""


class TSharkTimeoutError(TSharkUnavailable):
    """A TShark command did not finish within the configured timeout."""


class TSharkPermissionError(TSharkUnavailable):
    """TShark was not allowed to read the capture or capture on the host."""


class TSharkOutputError(TSharkUnavailable):
    """TShark produced output that could not be understood."""


class TSharkCommandError(TSharkUnavailable):
    """A TShark command failed (non-zero exit code)."""

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stderr: str = "",
        command: Sequence[str] = (),
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr
        self.command = tuple(command)


#: Backwards compatible alias - every error of this module is a ``TSharkError``.
TSharkError = TSharkUnavailable


@dataclass(frozen=True)
class TSharkVersion:
    """Version information reported by ``tshark -v``."""

    raw: str
    number: str | None = None
    product: str | None = None

    def __str__(self) -> str:
        return self.number or self.raw


@dataclass(frozen=True)
class TSharkInterface:
    """One capture interface reported by ``tshark -D``."""

    index: int
    name: str
    description: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"index": self.index, "name": self.name, "description": self.description}


@dataclass
class TSharkStatus:
    """Availability of the TShark toolchain."""

    available: bool
    path: str | None = None
    version: TSharkVersion | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "path": self.path,
            "version": self.version.number if self.version else None,
            "error": self.error,
        }


@dataclass
class FieldExtraction:
    """Result of a structured ``-T fields`` extraction."""

    records: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False
    timed_out: bool = False
    stderr: str = ""

    @property
    def count(self) -> int:
        return len(self.records)


def parse_version(output: str) -> TSharkVersion:
    """Parse the first meaningful line of ``tshark -v``."""

    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        match = _VERSION_RE.search(text)
        if not match:
            continue
        product = text.split(match.group("number"), 1)[0].strip(" -(") or None
        return TSharkVersion(raw=text, number=match.group("number"), product=product)
    raise TSharkOutputError("could not parse the TShark version output")


def parse_interfaces(output: str) -> list[TSharkInterface]:
    """Parse the output of ``tshark -D`` / ``dumpcap -D``.

    The format is ``<index>. <name>`` optionally followed by a friendly name
    in parentheses: ``3. lo (Loopback)``.
    """

    interfaces: list[TSharkInterface] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _INTERFACE_RE.match(line)
        if not match:
            continue
        rest = match.group("rest")
        friendly_match = _INTERFACE_FRIENDLY_RE.match(rest)
        if friendly_match:
            name = friendly_match.group("name").strip()
            description = friendly_match.group("friendly").strip() or None
        else:
            name = rest.strip()
            description = None
        if not name:
            continue
        interfaces.append(
            TSharkInterface(index=int(match.group("index")), name=name, description=description)
        )
    return interfaces


def _looks_like_permission_problem(stderr: str) -> bool:
    lowered = (stderr or "").lower()
    return any(marker in lowered for marker in _PERMISSION_MARKERS)


def _first_error_line(stderr: str) -> str | None:
    for line in (stderr or "").splitlines():
        text = line.strip()
        if text:
            return text
    return None


class TSharkAdapter:
    """Typed wrapper around the ``tshark`` executable."""

    def __init__(
        self,
        executable: Optional[str] = None,
        *,
        timeout: Optional[float] = None,
    ) -> None:
        # ``None`` means: resolve through the application configuration.
        self.executable = executable
        self.timeout = float(timeout if timeout is not None else config.TSHARK_TIMEOUT_SECONDS)

    # ------------------------------------------------------------------
    # executable discovery
    # ------------------------------------------------------------------
    @property
    def binary(self) -> Optional[str]:
        """The resolved path of the TShark binary (``None`` when missing)."""

        if self.executable is not None:
            return self.executable
        return config.TSHARK_PATH

    def find_executable(self) -> Optional[str]:
        """Return the path of the TShark binary or ``None``."""

        binary = self.binary
        if not binary:
            return None
        found = shutil.which(binary)
        if found:
            return found
        candidate = Path(binary)
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            return str(candidate)
        return None

    def is_available(self) -> bool:
        """``True`` when the binary exists and answers a version probe."""

        if not self.find_executable():
            return False
        try:
            self.version()
        except TSharkUnavailable:
            return False
        return True

    def require_executable(self) -> str:
        """Return the binary path or raise :class:`TSharkNotFoundError`."""

        path = self.find_executable()
        if path is None:
            raise TSharkNotFoundError(
                "TShark is not available on this system. Install Wireshark "
                "(package 'tshark') or set the TRAFFIC_ANALYZER_TSHARK "
                "environment variable to the absolute path of the binary."
            )
        return path

    # ------------------------------------------------------------------
    # command execution
    # ------------------------------------------------------------------
    def build_command(self, args: Sequence[str]) -> list[str]:
        return [self.require_executable(), *[str(arg) for arg in args]]

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: Optional[float] = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run TShark with an argument list and a bounded timeout."""

        command = self.build_command(args)
        effective_timeout = self.timeout if timeout is None else float(timeout)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
            )
        except FileNotFoundError as exc:  # pragma: no cover - race condition
            raise TSharkNotFoundError(
                "the TShark executable could not be started"
            ) from exc
        except PermissionError as exc:
            raise TSharkPermissionError(
                "not allowed to execute TShark; check the permissions of the binary"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise TSharkTimeoutError(
                f"TShark did not finish within {effective_timeout:g} seconds"
            ) from exc

        if check and completed.returncode != 0:
            stderr = completed.stderr or ""
            if _looks_like_permission_problem(stderr):
                raise TSharkPermissionError(
                    "TShark was not allowed to read this capture file."
                )
            raise TSharkCommandError(
                f"TShark failed: {_first_error_line(stderr) or 'unknown error'}",
                returncode=completed.returncode,
                stderr=stderr,
                command=command,
            )
        return completed

    # ------------------------------------------------------------------
    # high level queries
    # ------------------------------------------------------------------
    def version(self) -> TSharkVersion:
        """Return the parsed TShark version."""

        completed = self.run(["-v"], check=False)
        if completed.returncode != 0:
            stderr = completed.stderr or ""
            if _looks_like_permission_problem(stderr):
                raise TSharkPermissionError(
                    "not allowed to execute TShark; check the permissions of the binary"
                )
            raise TSharkCommandError(
                "could not determine the TShark version: "
                f"{_first_error_line(stderr) or 'unknown error'}",
                returncode=completed.returncode,
                stderr=stderr,
                command=(self.binary or "tshark", "-v"),
            )
        return parse_version(completed.stdout or "")

    def status(self) -> TSharkStatus:
        """Return a structured availability report (never raises)."""

        try:
            path = self.require_executable()
        except TSharkUnavailable as exc:
            return TSharkStatus(available=False, path=None, version=None, error=str(exc))
        try:
            version = self.version()
        except TSharkUnavailable as exc:
            return TSharkStatus(available=False, path=path, version=None, error=str(exc))
        return TSharkStatus(available=True, path=path, version=version, error=None)

    def interfaces(self) -> list[TSharkInterface]:
        """List the capture interfaces known to TShark."""

        completed = self.run(["-D"], check=False)
        stderr = completed.stderr or ""
        if completed.returncode != 0:
            if _looks_like_permission_problem(stderr):
                raise TSharkPermissionError(
                    "TShark was not allowed to list the capture interfaces."
                )
            raise TSharkCommandError(
                "could not list the capture interfaces: "
                f"{_first_error_line(stderr) or 'unknown error'}",
                returncode=completed.returncode,
                stderr=stderr,
                command=(self.binary or "tshark", "-D"),
            )
        interfaces = parse_interfaces(completed.stdout or "")
        if not interfaces:
            raise TSharkOutputError(
                "TShark did not report any capture interface (malformed output)"
            )
        return interfaces

    # ------------------------------------------------------------------
    # structured dissection
    # ------------------------------------------------------------------
    @staticmethod
    def build_dissect_command(
        capture_path: Path | str,
        fields: Sequence[str] = DISSECT_FIELDS,
    ) -> list[str]:
        """Build the argument list for a structured ``-T fields`` dissection."""

        args: list[str] = [
            "-n",
            "-r",
            str(capture_path),
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            f"separator={FIELD_SEPARATOR}",
            "-E",
            "quote=n",
            "-E",
            "occurrence=f",
        ]
        for field_name in fields:
            args += ["-e", field_name]
        return args

    def dissect(
        self,
        capture_path: Path | str,
        fields: Sequence[str] = DISSECT_FIELDS,
        *,
        timeout: Optional[float] = None,
    ) -> list[dict[str, str]]:
        """Dissect a capture file into one dictionary per frame.

        The dictionary keys are the TShark field names; an absent value is an
        empty string.
        """

        file_path = Path(capture_path)
        if not file_path.exists():
            raise TSharkNotFoundError(f"the capture file '{file_path.name}' does not exist")
        if not file_path.is_file():
            raise TSharkNotFoundError(
                f"'{file_path.name}' is not a regular file"
            )
        if file_path.stat().st_size == 0:
            raise TSharkCommandError(
                f"the capture file '{file_path.name}' is empty"
            )

        args = self.build_dissect_command(file_path, fields)
        command = self.build_command(args)
        effective_timeout = self.timeout if timeout is None else float(timeout)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
            )
        except FileNotFoundError as exc:  # pragma: no cover - race condition
            raise TSharkNotFoundError("the TShark executable could not be started") from exc
        except PermissionError as exc:
            raise TSharkPermissionError(
                "not allowed to execute TShark; check the permissions of the binary"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise TSharkTimeoutError(
                f"TShark did not finish within {effective_timeout:g} seconds"
            ) from exc

        stderr = completed.stderr or ""
        if completed.returncode != 0:
            if _looks_like_permission_problem(stderr):
                raise TSharkPermissionError(
                    "TShark was not allowed to read this capture file."
                )
            raise TSharkCommandError(
                f"TShark could not read '{file_path.name}': "
                f"{_first_error_line(stderr) or 'unknown error'}",
                returncode=completed.returncode,
                stderr=stderr,
                command=command,
            )

        return parse_field_rows(completed.stdout or "", fields)


def parse_field_rows(output: str, fields: Sequence[str]) -> list[dict[str, str]]:
    """Parse TShark's tab separated field output into dictionaries.

    The first line is the header row that TShark writes.  TShark lower-cases
    the header (it prints ``_ws.col.protocol`` for ``_ws.col.Protocol``), so
    the values are mapped back onto the requested field names by position.
    """

    lines = output.splitlines()
    if not lines:
        return []

    header = lines[0].split("\t")
    if len(header) != len(fields):
        # Not a header row (or an unexpected one): treat every line as data.
        header = None
        body = lines
    else:
        body = lines[1:]

    records: list[dict[str, str]] = []
    for line in body:
        if not line:
            continue
        values = line.split("\t")
        record: dict[str, str] = {}
        for index, name in enumerate(fields):
            record[name] = values[index] if index < len(values) else ""
        records.append(record)
    return records


# ----------------------------------------------------------------------
# frozen module level interface
# ----------------------------------------------------------------------
def _adapter() -> TSharkAdapter:
    return TSharkAdapter()


def is_available() -> bool:
    """``True`` when a usable TShark binary is installed."""

    return _adapter().is_available()


def tshark_version() -> Optional[str]:
    """Return the TShark version as reported by ``tshark --version``.

    ``None`` is returned when TShark is not available.
    """

    adapter = _adapter()
    try:
        binary = adapter.require_executable()
    except TSharkUnavailable:
        return None
    try:
        completed = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=config.TSHARK_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    for line in (completed.stdout or "").splitlines():
        text = line.strip()
        if text:
            return text
    return None


def dissect_file(path: str | Path) -> list[dict[str, str]]:
    """Dissect a capture file into one dictionary per frame.

    Every dictionary is keyed by the TShark field name; an absent value is an
    empty string.  An empty (but valid) capture returns an empty list and is
    not an error.  Every failure raises a subclass of
    :class:`TSharkUnavailable`.
    """

    return _adapter().dissect(Path(path), DISSECT_FIELDS)


def list_interfaces() -> list[dict]:
    """List the capture interfaces of this machine.

    TShark is preferred.  When TShark is not installed, ``dumpcap`` is used as
    a fallback.  When neither tool is available an empty list is returned -
    that is a normal state, not an error.
    """

    adapter = _adapter()
    try:
        interfaces = adapter.interfaces()
    except TSharkNotFoundError:
        interfaces = _dumpcap_interfaces()
    except TSharkUnavailable as exc:
        LOGGER.warning("listing the capture interfaces failed: %s", exc)
        interfaces = _dumpcap_interfaces()
    return [item.as_dict() for item in interfaces]


def _dumpcap_interfaces() -> list[TSharkInterface]:
    """Fallback interface listing through ``dumpcap``."""

    binary = config.DUMPCAP_PATH
    if not binary:
        return []
    resolved = shutil.which(binary) or (
        binary if Path(binary).is_file() and os_access_executable(binary) else None
    )
    if not resolved:
        return []
    try:
        completed = subprocess.run(
            [resolved, "-D"],
            capture_output=True,
            text=True,
            timeout=config.TSHARK_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    return parse_interfaces(completed.stdout or "")


def os_access_executable(path: str) -> bool:
    """Return ``True`` when the file at ``path`` is executable."""

    import os

    try:
        return os.access(path, os.X_OK)
    except OSError:  # pragma: no cover - defensive
        return False


# ----------------------------------------------------------------------
# packet counting (no external tool required)
# ----------------------------------------------------------------------
def count_packets(path: str | Path) -> Optional[int]:
    """Count the packets stored in a pcap or pcapng file.

    The count is derived from the file structure, so it also works for a file
    that is still being written.  ``None`` is returned when the format is not
    understood.
    """

    file_path = Path(path)
    try:
        with file_path.open("rb") as handle:
            head = handle.read(4)
            if not head:
                return None
            if head in _PCAP_MAGICS:
                return _count_pcap(handle, head)
            if head == _PCAPNG_MAGIC:
                return _count_pcapng(handle)
    except OSError:
        return None
    return None


def _count_pcap(handle, magic: bytes) -> Optional[int]:
    import struct

    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    handle.seek(24)
    count = 0
    while True:
        header = handle.read(16)
        if len(header) < 16:
            break
        incl_len = struct.unpack(endian + "I", header[8:12])[0]
        if incl_len > 16 * 1024 * 1024:
            break
        handle.seek(incl_len, 1)
        count += 1
    return count


def _count_pcapng(handle) -> Optional[int]:
    """Count the packet blocks of a pcapng file.

    Works on a file that is still being written: the blocks that are complete are
    counted, the incomplete tail is ignored.
    """
    import struct

    count = 0
    endian = "<"
    # The caller already consumed the 4 byte magic, so the first block is re-read
    # from the beginning of the file.
    handle.seek(0)
    while True:
        header = handle.read(8)
        if len(header) < 8:
            break
        block_type = struct.unpack("<I", header[0:4])[0]
        total_length = struct.unpack(endian + "I", header[4:8])[0]
        if total_length < 12 or total_length > 64 * 1024 * 1024:
            # The length may have been read with the wrong byte order (the first
            # block decides the order), so the other one is tried.
            other = ">" if endian == "<" else "<"
            candidate = struct.unpack(other + "I", header[4:8])[0]
            if 12 <= candidate <= 64 * 1024 * 1024:
                endian = other
                total_length = candidate
            else:
                break

        body = handle.read(total_length - 12)
        trailer = handle.read(4)
        if len(body) < total_length - 12 or len(trailer) < 4:
            break

        if block_type == 0x0A0D0D0A:  # Section Header Block: it decides the byte order
            if len(body) >= 4:
                bom = body[:4]
                if bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                elif bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
        elif block_type in (0x00000006, 0x00000003):  # Enhanced / Simple Packet Block
            count += 1
    return count
