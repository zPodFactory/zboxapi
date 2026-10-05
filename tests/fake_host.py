"""An in-memory zcore: disks, partitions, LVM, mounts and exports.

`FakeHost.run` stands in for subprocess.run. Read commands render the model (`lsblk -J`,
`exportfs -v`); mutating commands change it (added per phase). Unknown commands fall
through to the FakeSystem of the dns and vlan tests, so one client fixture serves every
router.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

G = 1024**3
T = 1024**4


@dataclass
class Part:
    name: str
    size: int
    fstype: str | None = None
    label: str | None = None
    uuid: str | None = None
    mountpoint: str | None = None
    parttype: str | None = None


@dataclass
class LV:
    vg: str
    name: str
    size: int
    pv: str  # partition name
    fstype: str | None = "ext4"
    label: str | None = None
    uuid: str | None = None
    mountpoint: str | None = None

    @property
    def dm_name(self) -> str:
        return f"{self.vg.replace('-', '--')}-{self.name.replace('-', '--')}"


@dataclass
class Disk:
    name: str
    size: int
    serial: str = ""
    model: str = "Virtual disk"
    pttype: str | None = None
    fstype: str | None = None  # a signature directly on the disk (foreign)
    parts: list[Part] = field(default_factory=list)
    rescans: int = 0  # writes to /sys/class/block/<name>/device/rescan


class FakeHost:
    def __init__(self, fallback=None):
        self.disks: dict[str, Disk] = {}
        self.lvs: list[LV] = []
        self.exports_files: list[Path] = []  # exportfs -ra reads these
        self.active_exports: dict[str, list[str]] = {}
        self.calls: list[list[str]] = []
        self.mutating_calls: list[list[str]] = []
        self.fallback = fallback
        self.fail: set[tuple[str, ...]] = set()

    # ── model helpers ──────────────────────────────────────────────────────────
    def add_disk(self, name: str, size: int, **kw) -> Disk:
        disk = Disk(
            name=name, size=size, serial=kw.pop("serial", f"6000c29{name}"), **kw
        )
        self.disks[name] = disk
        return disk

    def add_part(self, disk: str, size: int | None = None, **kw) -> Part:
        d = self.disks[disk]
        d.pttype = d.pttype or "gpt"
        part = Part(
            name=f"{disk}{len(d.parts) + 1}", size=size or d.size - 2 * 1024**2, **kw
        )
        d.parts.append(part)
        return part

    def add_lv(self, vg: str, name: str, pv: str, **kw) -> LV:
        part = self._part(pv)
        part.fstype = "LVM2_member"
        part.parttype = "e6d6d379-f507-44c2-a23c-238f2a3df928"
        lv = LV(
            vg=vg, name=name, pv=pv, size=kw.pop("size", part.size - 4 * 1024**2), **kw
        )
        self.lvs.append(lv)
        return lv

    def snapshot(self, disk: str) -> str:
        """A stable rendering of one disk and everything on it, for invariant checks."""
        d = self.disks[disk]
        return json.dumps(
            {
                "disk": d.__dict__,
                "parts": [p.__dict__ for p in d.parts],
                "lvs": [
                    lv.__dict__ for lv in self.lvs if lv.pv in {p.name for p in d.parts}
                ],
            },
            default=str,
            sort_keys=True,
        )

    def _part(self, name: str) -> Part:
        for d in self.disks.values():
            for p in d.parts:
                if p.name == name:
                    return p
        raise KeyError(name)

    # ── renderers ──────────────────────────────────────────────────────────────
    def lsblk(self) -> str:
        devices = []
        for d in self.disks.values():
            parts = []
            for p in d.parts:
                node = {
                    "name": p.name,
                    "path": f"/dev/{p.name}",
                    "size": p.size,
                    "type": "part",
                    "fstype": p.fstype,
                    "label": p.label,
                    "mountpoint": p.mountpoint,
                    "pttype": d.pttype,
                    "parttype": p.parttype,
                    "uuid": p.uuid,
                    "pkname": d.name,
                    "serial": None,
                    "model": None,
                    "children": [
                        {
                            "name": lv.dm_name,
                            "path": f"/dev/mapper/{lv.dm_name}",
                            "size": lv.size,
                            "type": "lvm",
                            "fstype": lv.fstype,
                            "label": lv.label,
                            "mountpoint": lv.mountpoint,
                            "pttype": None,
                            "parttype": None,
                            "uuid": lv.uuid,
                            "pkname": p.name,
                            "serial": None,
                            "model": None,
                        }
                        for lv in self.lvs
                        if lv.pv == p.name
                    ],
                }
                parts.append(node)
            devices.append(
                {
                    "name": d.name,
                    "path": f"/dev/{d.name}",
                    "size": d.size,
                    "type": "disk",
                    "fstype": d.fstype,
                    "label": None,
                    "mountpoint": None,
                    "pttype": d.pttype,
                    "parttype": None,
                    "uuid": None,
                    "pkname": None,
                    "serial": d.serial,
                    "model": d.model,
                    "children": parts,
                }
            )
        return json.dumps({"blockdevices": devices})

    def exportfs_v(self) -> str:
        lines = []
        for path, clients in sorted(self.active_exports.items()):
            for client in clients:
                shown = "<world>" if client == "*" else client
                opts = "rw,sync,wdelay,no_root_squash,no_subtree_check"
                if len(path) > 14:
                    lines += [path, f"\t\t{shown}({opts})"]
                else:
                    lines.append(f"{path:<16}{shown}({opts})")
        return "\n".join(lines) + ("\n" if lines else "")

    def reload_exports(self) -> None:
        """What `exportfs -ra` does: the files become the active table."""
        from zboxapi.nfs import parse_exports

        table: dict[str, list[str]] = {}
        for path in self.exports_files:
            if path.is_file():
                for export_path, clients in parse_exports(path.read_text()).items():
                    table.setdefault(export_path, []).extend(c.client for c in clients)
        self.active_exports = table

    # ── subprocess.run stand-in ────────────────────────────────────────────────
    def run(self, cmd, **kwargs) -> subprocess.CompletedProcess:
        cmd = list(cmd)
        self.calls.append(cmd)
        rc, out, err = self._dispatch(cmd)
        if rc == 127 and self.fallback is not None:
            return self.fallback.run(cmd, **kwargs)
        if kwargs.get("check") and rc != 0:
            raise subprocess.CalledProcessError(rc, cmd, output=out, stderr=err)
        return subprocess.CompletedProcess(cmd, rc, out, err)

    def _dispatch(self, cmd: list[str]) -> tuple[int, str, str]:
        for prefix in self.fail:
            if tuple(cmd[: len(prefix)]) == prefix:
                return 1, "", f"fake failure: {' '.join(cmd)}"
        match cmd:
            case ["lsblk", *_]:
                return 0, self.lsblk(), ""
            case ["exportfs", "-v"]:
                return 0, self.exportfs_v(), ""
            case ["exportfs", "-ra"] | ["exportfs", "-r"]:
                self.mutating_calls.append(cmd)
                self.reload_exports()
                return 0, "", ""
        return 127, "", f"unknown command: {cmd}"


def zcore(tmp_path: Path) -> FakeHost:
    """zcore as it is today: sda system, sdb1 ext4 on /FILER/STORAGE01."""
    host = FakeHost()
    sda = host.add_disk("sda", 50 * G, pttype="dos", serial="6000c29sda")
    host.add_part("sda", 46 * G, fstype="ext4", uuid="aaaa-root", mountpoint="/")
    sdb = host.add_disk("sdb", T, serial="6000c29sdb")
    host.add_part(
        "sdb",
        T - 2 * 1024**2,
        fstype="ext4",
        label="STORAGE01",
        uuid="bbbb-storage01",
        mountpoint=str(tmp_path / "FILER" / "STORAGE01"),
    )
    assert sda and sdb
    return host
