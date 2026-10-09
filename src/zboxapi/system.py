"""One door to the host for the storage and nfs routers.

`query()` runs read-only commands and `run()` runs the ones that change the host. Every
mutating argv is checked against the protected set before it executes (the second guard
layer, see guard.py) and is appended to the audit log with its exit status. The existing
dns and vlan routers keep calling subprocess directly; they predate this module.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

# Module-level so tests can redirect them
AUDIT_LOG = Path("/var/log/zboxapi-storage.log")
LOCK_FILE = Path("/run/zboxapi-storage.lock")
SYS_BLOCK = Path("/sys/class/block")
SYS_SCSI_HOST = Path("/sys/class/scsi_host")

# Commands that only read the host. Matched as a prefix of argv.
READ_ONLY: tuple[tuple[str, ...], ...] = (
    ("lsblk",),
    ("findmnt",),
    ("blkid",),
    ("wipefs", "-n"),
    ("exportfs", "-v"),
    ("exportfs", "-s"),
    ("showmount",),
    ("nft", "-j", "list"),
    ("nft", "list"),
    ("vgs",),
    ("lvs",),
    ("pvs",),
    ("systemctl", "is-active"),
    ("systemctl", "is-enabled"),
    ("systemctl", "show"),
)

LSBLK_COLUMNS = ",".join(
    [
        "NAME",
        "PATH",
        "SIZE",
        "TYPE",
        "FSTYPE",
        "LABEL",
        "MOUNTPOINT",
        "PTTYPE",
        "PARTTYPE",
        "UUID",
        "PKNAME",
        "SERIAL",
        "MODEL",
    ]
)


class CommandError(Exception):
    """A host command failed."""

    def __init__(self, argv: list[str], result: subprocess.CompletedProcess):
        self.argv = argv
        self.result = result
        super().__init__(
            f"{' '.join(argv)} failed ({result.returncode}): "
            f"{(result.stderr or result.stdout or '').strip()}"
        )


def is_read_only(argv: list[str]) -> bool:
    return any(tuple(argv[: len(prefix)]) == prefix for prefix in READ_ONLY)


def query(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    """Run a read-only command. Refuses anything not on the allowlist."""
    if not is_read_only(argv):
        raise ValueError(f"not a read-only command: {' '.join(argv)}")
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise CommandError(argv, result)
    return result


def run(
    argv: list[str],
    *,
    check: bool = True,
    input: str | None = None,
    source: str = "",
) -> subprocess.CompletedProcess:
    """Run a command that changes the host: guarded, then logged."""
    from zboxapi import guard  # late import: guard queries the host through this module

    guard.assert_argv_allowed(argv)
    result = subprocess.run(
        argv, capture_output=True, text=True, check=False, input=input
    )
    audit(argv, result.returncode, source)
    if check and result.returncode != 0:
        raise CommandError(argv, result)
    return result


def write_sysfs(path: Path, value: str, *, source: str = "") -> None:
    """A guarded write to a sysfs node (rescan triggers)."""
    from zboxapi import guard

    guard.assert_argv_allowed(["sysfs-write", str(path)])
    path.write_text(value)
    audit(["sysfs-write", str(path), value.strip()], 0, source)


def audit(argv: list[str], returncode: int, source: str) -> None:
    line = (
        f"[{dt.datetime.now().isoformat(timespec='seconds')}] "
        f"{source or '-'} rc={returncode} {' '.join(argv)}\n"
    )
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as fo:
            fo.write(line)
    except OSError:
        pass  # the audit log must never make an operation fail


@contextlib.contextmanager
def storage_lock():
    """One lock for every mutating storage and nfs operation."""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a+") as fo:
        while True:
            try:
                fcntl.flock(fo, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(fo, fcntl.LOCK_UN)


# ── block device inventory ───────────────────────────────────────────────────────────


@dataclass
class BlockNode:
    """One row of lsblk, with its children."""

    name: str
    path: str
    size: int
    type: str  # disk | part | lvm | ...
    fstype: str | None = None
    label: str | None = None
    mountpoint: str | None = None
    pttype: str | None = None
    parttype: str | None = None
    uuid: str | None = None
    pkname: str | None = None
    serial: str | None = None
    model: str | None = None
    children: list[BlockNode] = field(default_factory=list)
    parent: BlockNode | None = field(default=None, repr=False)

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    @property
    def disk(self) -> BlockNode:
        node = self
        while node.parent is not None:
            node = node.parent
        return node

    @property
    def vg(self) -> str | None:
        return split_dm_name(self.name)[0] if self.type == "lvm" else None

    @property
    def lv(self) -> str | None:
        return split_dm_name(self.name)[1] if self.type == "lvm" else None


def split_dm_name(name: str) -> tuple[str, str]:
    """`vg_storage02-data` -> (`vg_storage02`, `data`). A literal hyphen is doubled."""
    out, i, parts = "", 0, []
    while i < len(name):
        if name[i] == "-" and i + 1 < len(name) and name[i + 1] == "-":
            out, i = out + "-", i + 2
        elif name[i] == "-":
            parts.append(out)
            out, i = "", i + 1
        else:
            out, i = out + name[i], i + 1
    parts.append(out)
    return (parts[0], "-".join(parts[1:])) if len(parts) > 1 else (name, "")


def _node(raw: dict, parent: BlockNode | None) -> BlockNode:
    node = BlockNode(
        name=raw["name"],
        path=raw.get("path") or f"/dev/{raw['name']}",
        size=int(raw.get("size") or 0),
        type=raw.get("type") or "",
        fstype=raw.get("fstype"),
        label=raw.get("label"),
        mountpoint=raw.get("mountpoint"),
        pttype=raw.get("pttype"),
        parttype=raw.get("parttype"),
        uuid=raw.get("uuid"),
        pkname=raw.get("pkname"),
        serial=raw.get("serial"),
        model=raw.get("model"),
        parent=parent,
    )
    node.children = [_node(c, node) for c in raw.get("children", [])]
    return node


def block_devices() -> list[BlockNode]:
    """Every disk with its partitions and LVM volumes, sizes in bytes."""
    result = query(["lsblk", "-J", "-b", "-o", LSBLK_COLUMNS])
    raw = json.loads(result.stdout or '{"blockdevices": []}')
    return [_node(d, None) for d in raw.get("blockdevices", [])]


def find_mounted(
    mountpoint: str, nodes: list[BlockNode] | None = None
) -> BlockNode | None:
    for disk in nodes if nodes is not None else block_devices():
        for node in disk.walk():
            if node.mountpoint == mountpoint:
                return node
    return None


# ── reading the audit log back ───────────────────────────────────────────────────────

AUDIT_LINE = re.compile(
    r"^\[(?P<time>[^\]]+)\] (?P<source>\S+) rc=(?P<rc>-?\d+) (?P<command>.*)$"
)


def audit_entries(limit: int = 50) -> list[dict]:
    """The newest `limit` audit lines, newest first."""
    try:
        lines = AUDIT_LOG.read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        m = AUDIT_LINE.match(line)
        if not m:
            continue
        out.append(
            {
                "time": m.group("time"),
                "source": m.group("source"),
                "rc": int(m.group("rc")),
                "command": m.group("command"),
            }
        )
        if len(out) >= limit:
            break
    return out
