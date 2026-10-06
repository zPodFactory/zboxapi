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
LVM_COMMANDS = {
    "pvcreate",
    "vgcreate",
    "lvcreate",
    "pvresize",
    "lvextend",
    "pvremove",
    "vgremove",
    "lvremove",
}


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
        self.lvm_installed = True
        # sysfs: rescan nodes the API writes; the model reacts when it renders lsblk
        self.sysfs: Path | None = None
        self.pending_disks: list[Disk] = []  # appear after a SCSI host scan
        self.pending_sizes: dict[str, int] = {}  # applied after the disk's rescan
        self.unit_dir: Path | None = None  # where systemctl finds *.mount units
        self.units_enabled: set[str] = set()

    # ── model helpers ──────────────────────────────────────────────────────────
    def add_disk(self, name: str, size: int, **kw) -> Disk:
        disk = Disk(
            name=name, size=size, serial=kw.pop("serial", f"6000c29{name}"), **kw
        )
        self.disks[name] = disk
        self._sysfs_node(name)
        return disk

    def attach_sysfs(self, root: Path) -> None:
        """Create /sys/class/block/<disk>/device/rescan and scsi_host/host0/scan."""
        self.sysfs = root
        (root / "scsi_host" / "host0").mkdir(parents=True, exist_ok=True)
        (root / "scsi_host" / "host0" / "scan").write_text("")
        for name in self.disks:
            self._sysfs_node(name)

    def _sysfs_node(self, name: str) -> None:
        if self.sysfs is not None:
            node = self.sysfs / "block" / name / "device"
            node.mkdir(parents=True, exist_ok=True)
            (node / "rescan").write_text("")
            (node / "delete").write_text("")

    def hotplug(self, disk: Disk) -> None:
        """A disk attached in vSphere: visible after the next SCSI host scan."""
        self.pending_disks.append(disk)

    def resize(self, name: str, size: int) -> None:
        """A disk enlarged in vSphere: visible after the next rescan of that disk."""
        self.pending_sizes[name] = size

    def _apply_sysfs(self) -> None:
        if self.sysfs is None:
            return
        scan = self.sysfs / "scsi_host" / "host0" / "scan"
        if scan.exists() and scan.read_text().strip() == "- - -":
            scan.write_text("")
            for disk in self.pending_disks:
                self.disks[disk.name] = disk
                self._sysfs_node(disk.name)
            self.pending_disks = []
        for name, disk in list(self.disks.items()):
            node = self.sysfs / "block" / name / "device" / "rescan"
            if node.exists() and node.read_text().strip() == "1":
                node.write_text("")
                disk.rescans += 1
                if name in self.pending_sizes:
                    disk.size = self.pending_sizes.pop(name)
            delete = self.sysfs / "block" / name / "device" / "delete"
            if delete.exists() and delete.read_text().strip() == "1":
                del self.disks[name]  # the kernel forgot the device
                self.detached = getattr(self, "detached", []) + [name]

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

    def snapshot(self, disk: str, *, sizes: bool = True) -> str:
        """A stable rendering of one disk and everything on it, for invariant checks.
        `sizes=False` leaves sizes and rescan counts out: growing may change those."""
        d = self.disks[disk]

        def fields(obj):
            return {
                k: v
                for k, v in obj.__dict__.items()
                if sizes or k not in ("size", "rescans")
            }

        return json.dumps(
            {
                "disk": {k: v for k, v in fields(d).items() if k != "parts"},
                "parts": [fields(p) for p in d.parts],
                "lvs": [
                    fields(lv) for lv in self.lvs if lv.pv in {p.name for p in d.parts}
                ],
            },
            default=str,
            sort_keys=True,
        )

    def sizes(self, disk: str) -> list[int]:
        d = self.disks[disk]
        return (
            [d.size]
            + [p.size for p in d.parts]
            + [lv.size for lv in self.lvs if lv.pv in {p.name for p in d.parts}]
        )

    def _part(self, name: str) -> Part:
        for d in self.disks.values():
            for p in d.parts:
                if p.name == name:
                    return p
        raise KeyError(name)

    # ── renderers ──────────────────────────────────────────────────────────────
    def lsblk(self) -> str:
        self._apply_sysfs()
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
        rc, out, err = self._dispatch(cmd, kwargs.get("input"))
        if rc == 127 and self.fallback is not None:
            return self.fallback.run(cmd, **kwargs)
        if kwargs.get("check") and rc != 0:
            raise subprocess.CalledProcessError(rc, cmd, output=out, stderr=err)
        return subprocess.CompletedProcess(cmd, rc, out, err)

    def _dispatch(  # noqa: C901
        self, cmd: list[str], stdin: str | None = None
    ) -> tuple[int, str, str]:
        self._apply_sysfs()  # a rescan write takes effect before the next command runs
        for prefix in self.fail:
            if tuple(cmd[: len(prefix)]) == prefix:
                return 2, "", f"fake failure: {' '.join(cmd)}"
        if cmd[0] in LVM_COMMANDS and not self.lvm_installed:
            return 127, "", f"{cmd[0]}: command not found"
        match cmd:
            case ["lsblk", *_]:
                return 0, self.lsblk(), ""
            case ["exportfs", "-v"]:
                return 0, self.exportfs_v(), ""
            case ["showmount", "-a", "--no-headers"]:
                mounts = getattr(self, "v3_mounts", [])  # (host, path)
                return 0, "".join(f"{h}:{p}\n" for h, p in mounts), ""
            case ["systemctl", "is-active", "nfs-server"]:
                return 0, getattr(self, "nfs_state", "active") + "\n", ""
            case ["systemctl", "is-enabled", "nfs-server"]:
                return 0, "enabled\n", ""
            case ["exportfs", "-ra"] | ["exportfs", "-r"]:
                self.mutating_calls.append(cmd)
                self.reload_exports()
                return 0, "", ""
            case (
                ["udevadm", "settle"]
                | ["partx", "-u", _]
                | ["systemctl", "daemon-reload"]
            ):
                return 0, "", ""
            case ["sfdisk", *_, path]:
                return self._sfdisk(cmd, path, stdin or "")
            case ["wipefs", "-a", path]:
                return self._wipefs(cmd, path)
            case ["pvcreate", *_, path]:
                self.mutating_calls.append(cmd)
                part = self._part(path.removeprefix("/dev/"))
                part.fstype = "LVM2_member"
                return 0, f'Physical volume "{path}" successfully created.', ""
            case ["pvremove", *_, path]:
                self.mutating_calls.append(cmd)
                self._part(path.removeprefix("/dev/")).fstype = None
                return 0, "", ""
            case ["vgcreate", vg, path]:
                self.mutating_calls.append(cmd)
                self.vgs = getattr(self, "vgs", {})
                self.vgs[vg] = path.removeprefix("/dev/")
                return 0, f'Volume group "{vg}" successfully created', ""
            case ["vgremove", *_, vg]:
                self.mutating_calls.append(cmd)
                getattr(self, "vgs", {}).pop(vg, None)
                return 0, "", ""
            case ["lvcreate", *_, "-n", lv, vg]:
                self.mutating_calls.append(cmd)
                pv = getattr(self, "vgs", {})[vg]
                part = self._part(pv)
                self.lvs.append(
                    LV(vg=vg, name=lv, pv=pv, size=part.size - 4 * 1024**2, fstype=None)
                )
                return 0, f'Logical volume "{lv}" created.', ""
            case ["lvremove", *_, spec]:
                self.mutating_calls.append(cmd)
                vg, lv = spec.removeprefix("/dev/").split("/", 1)
                self.lvs = [x for x in self.lvs if not (x.vg == vg and x.name == lv)]
                return 0, "", ""
            case ["mkfs.ext4", *args, path]:
                return self._mkfs(cmd, args, path)
            case ["systemctl", "enable", "--now", unit]:
                return self._mount_unit(cmd, unit, up=True)
            case ["systemctl", "disable", "--now", unit]:
                return self._mount_unit(cmd, unit, up=False)
            case ["growpart", path, number]:
                return self._growpart(cmd, path, number)
            case ["pvresize", _]:
                self.mutating_calls.append(cmd)
                return 0, "", ""
            case ["lvextend", "-l", "+100%FREE", spec]:
                self.mutating_calls.append(cmd)
                vg, lv = spec.removeprefix("/dev/").split("/", 1)
                for x in self.lvs:
                    if x.vg == vg and x.name == lv:
                        new = self._part(x.pv).size - 4 * 1024**2
                        if new <= x.size:
                            return 5, "", "New size (in extents) matches existing size."
                        x.size = new
                return 0, "", ""
            case ["resize2fs", _]:
                self.mutating_calls.append(cmd)
                return 0, "", ""
        return 127, "", f"unknown command: {cmd}"

    # ── phase 3 command models ─────────────────────────────────────────────────
    def _node(self, path: str):
        name = path.removeprefix("/dev/")
        if name.startswith("mapper/"):
            dm = name.removeprefix("mapper/")
            return next(lv for lv in self.lvs if lv.dm_name == dm)
        if name in self.disks:
            return self.disks[name]
        if "/" in name:
            vg, lv = name.split("/", 1)
            return next(x for x in self.lvs if x.vg == vg and x.name == lv)
        return self._part(name)

    def _sfdisk(self, cmd, path, script):
        self.mutating_calls.append(cmd)
        disk = self.disks[path.removeprefix("/dev/")]
        if disk.parts or disk.pttype:
            return 1, "", f"{path}: already has a partition table"
        assert "label: gpt" in script
        kind = "lvm" if ",,lvm" in script else "linux"
        disk.pttype = "gpt"
        disk.parts.append(
            Part(
                name=f"{disk.name}1",
                size=disk.size - 2 * 1024**2,
                parttype="e6d6d379-f507-44c2-a23c-238f2a3df928"
                if kind == "lvm"
                else "0fc63daf-8483-4772-8e79-3d69d8477de4",
            )
        )
        return 0, "", ""

    def _wipefs(self, cmd, path):
        self.mutating_calls.append(cmd)
        node = self._node(path)
        if isinstance(node, Disk):
            node.pttype, node.fstype, node.parts = None, None, []
        else:
            node.fstype, node.label, node.uuid = None, None, None
        return 0, "", ""

    def _mkfs(self, cmd, args, path):
        self.mutating_calls.append(cmd)
        node = self._node(path)
        node.fstype = "ext4"
        node.label = args[args.index("-L") + 1] if "-L" in args else None
        node.uuid = args[args.index("-U") + 1] if "-U" in args else f"uuid-{path}"
        return 0, f"Creating filesystem with {node.size // 4096} 4k blocks", ""

    def _mount_unit(self, cmd, unit, up):
        self.mutating_calls.append(cmd)
        path = (self.unit_dir or Path(".")) / unit
        if not path.is_file():
            return 1, "", f"Failed to enable unit: Unit file {unit} does not exist."
        text = path.read_text()
        uuid = text.split("What=UUID=", 1)[1].splitlines()[0].strip()
        where = text.split("Where=", 1)[1].splitlines()[0].strip()
        target = next(
            (n for d in self.disks.values() for n in d.parts if n.uuid == uuid), None
        ) or next((lv for lv in self.lvs if lv.uuid == uuid), None)
        if target is None:
            return 1, "", f"mount: can't find UUID={uuid}"
        target.mountpoint = where if up else None
        (self.units_enabled.add if up else self.units_enabled.discard)(unit)
        return 0, "", ""

    def _growpart(self, cmd, path, number):
        self.mutating_calls.append(cmd)
        disk = self.disks[path.removeprefix("/dev/")]
        part = disk.parts[int(number) - 1]
        new = disk.size - 2 * 1024**2
        if new <= part.size:
            return (
                1,
                f"NOCHANGE: partition {number} is size {part.size // 512}. "
                "it cannot be grown",
                "",
            )
        old = part.size
        part.size = new
        return (
            0,
            f"CHANGED: partition={number} start=2048 "
            f"old: size={old // 512} new: size={new // 512}",
            "",
        )


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
