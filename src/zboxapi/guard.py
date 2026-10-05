"""The protected set: NFS-01, /FILER/STORAGE01, the disk behind it, everything on it.

Protected means never modified, with one deliberate exception: a protected storage may
be grown (rescan, growpart, pvresize, lvextend, resize2fs), because those steps only
ever add space and leave the data where it is. The command runner lets exactly those
command shapes through.

Computed on every request from the live block device tree, so it follows the mount
and not a device letter. STORAGE01 and NFS-01 are a floor: config can add to the set,
never remove them. Three enforcement points use it: the endpoints (`assert_mutable`),
the command runner (`assert_argv_allowed`, see system.py) and the file writers
(`assert_path_writable`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from zboxapi import config, system

PROTECTED_STORAGES_FLOOR = frozenset({"STORAGE01"})
PROTECTED_EXPORTS_FLOOR = frozenset({"/FILER/STORAGE01/NFS-01"})

STORAGE_NAME_RE = re.compile(r"^STORAGE\d{2,3}$")


class ProtectedError(Exception):
    """The target is in the protected set."""


@dataclass
class ProtectedSet:
    storages: set[str] = field(default_factory=set)  # STORAGE01
    mountpoints: set[str] = field(default_factory=set)  # /FILER/STORAGE01
    devices: set[str] = field(
        default_factory=set
    )  # sdb, /dev/sdb, sdb1, /dev/sdb1, dm paths
    vgs: set[str] = field(default_factory=set)  # vg names backed by a protected disk
    exports: set[str] = field(default_factory=set)  # /FILER/STORAGE01/NFS-01
    reasons: dict[str, str] = field(default_factory=dict)  # member -> why

    def reason_for(self, target: str) -> str | None:
        """The protection reason if `target` names or lies under a protected member."""
        t = target.strip()
        if t in self.devices or t in self.vgs or t in self.storages:
            return self.reasons.get(t)
        if t.startswith("/dev/") and t.removeprefix("/dev/") in self.devices:
            return self.reasons.get(t.removeprefix("/dev/"))
        for vg in self.vgs:
            if t.startswith(f"/dev/{vg}/") or t.startswith(f"/dev/mapper/{vg}-"):
                return self.reasons.get(vg)
        # The mountpoint itself (umount, rmdir, mount units); folders beneath it are
        # allowed by decision, except the protected exports and everything under them.
        if t.rstrip("/") in self.mountpoints:
            return self.reasons.get(t.rstrip("/"))
        for path in self.exports:
            if t == path or t.startswith(path + "/"):
                return self.reasons.get(path)
        return None


def filer_root() -> str:
    return config.get("storage", "filer_root").rstrip("/") or "/FILER"


def protected_storage_names() -> set[str]:
    return set(config.get_list("storage", "protected_storages")) | set(
        PROTECTED_STORAGES_FLOOR
    )


def protected_export_paths() -> set[str]:
    return set(config.get_list("nfs", "protected_exports")) | set(
        PROTECTED_EXPORTS_FLOOR
    )


def protected_set(nodes: list[system.BlockNode] | None = None) -> ProtectedSet:
    """Resolve the set from config and the live block tree."""
    ps = ProtectedSet()
    root = filer_root()
    if nodes is None:
        nodes = system.block_devices()

    for name in sorted(protected_storage_names()):
        mountpoint = f"{root}/{name}"
        reason = (
            f"{name} is protected: {mountpoint} and the disk behind it "
            "are never modified"
        )
        ps.storages.add(name)
        ps.reasons[name] = reason
        ps.mountpoints.add(mountpoint)
        ps.reasons[mountpoint] = reason
        mounted = system.find_mounted(mountpoint, nodes)
        if mounted is None:
            continue
        disk = mounted.disk
        _add_disk(ps, disk, f"{disk.name} is protected: it holds {mountpoint} ({name})")

    for path in sorted(protected_export_paths()):
        ps.exports.add(path)
        ps.reasons[path] = f"{path} is a protected export: never modified"

    # The system disk: whatever holds /, /boot or swap. Growing it is zbox-init's job.
    for disk in nodes:
        if disk.type != "disk" or disk.name in ps.devices:
            continue
        if any(is_system_node(n) for n in disk.walk()):
            _add_disk(ps, disk, f"{disk.name} is the system disk: never modified")
    return ps


def is_system_node(node: system.BlockNode) -> bool:
    return node.mountpoint in ("/", "/boot", "/boot/efi") or node.fstype == "swap"


def _add_disk(ps: ProtectedSet, disk: system.BlockNode, reason: str) -> None:
    for node in disk.walk():
        for member in (node.name, node.path):
            ps.devices.add(member)
            ps.reasons[member] = reason
        if node.type == "lvm" and node.vg:
            ps.vgs.add(node.vg)
            ps.reasons[node.vg] = reason
            for member in (f"/dev/{node.vg}/{node.lv}", f"/dev/mapper/{node.name}"):
                ps.devices.add(member)
                ps.reasons[member] = reason


# ── the three enforcement points ─────────────────────────────────────────────────────


def assert_mutable(target: str, ps: ProtectedSet | None = None) -> None:
    """Layer 1, at the endpoint: a disk, device, VG, mountpoint, folder or export."""
    ps = ps if ps is not None else protected_set()
    if reason := ps.reason_for(target):
        raise ProtectedError(reason)


def is_extend_only(argv: list[str]) -> bool:
    """The exact command shapes that can only make a filesystem bigger, never smaller
    and never different: growing is allowed on protected storages, nothing else is."""
    match argv:
        case ["growpart", _disk, number] if number.isdigit():
            return True
        case ["pvresize", _device]:
            return True
        case ["lvextend", "-l", "+100%FREE", _lv]:
            return True
        case ["resize2fs", _device]:  # no size argument: fill the device
            return True
        case ["sysfs-write", path] if path.endswith("/device/rescan"):
            return True
    return False


def assert_argv_allowed(argv: list[str]) -> None:
    """Layer 2, at the command runner: no mutating argv may name a protected member,
    unless the command is one of the extend-only shapes (see `is_extend_only`)."""
    if system.is_read_only(argv) or is_extend_only(argv):
        return
    ps = protected_set()
    for token in argv[1:]:
        for candidate in _candidates(token):
            if reason := ps.reason_for(candidate):
                raise ProtectedError(f"refused to run {' '.join(argv)}: {reason}")


def assert_path_writable(path: str, ps: ProtectedSet | None = None) -> None:
    """Layer 3, at the file writers: not a protected mountpoint or export path."""
    assert_mutable(path, ps)


def _candidates(token: str) -> list[str]:
    """Forms of a token naming a device: the token, `vg/lv`, sysfs block paths."""
    out = [token]
    if "=" in token:  # What=UUID=..., device=/dev/sdb
        out.append(token.split("=", 1)[1])
    m = re.match(r"^/sys/class/block/([^/]+)/", token)
    if m:
        out.append(m.group(1))
    if "/" in token and not token.startswith("/"):  # vg_storage02/data
        out.append("/dev/" + token)
    return out
