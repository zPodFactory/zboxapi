"""Block device inventory: what disks zcore has and what may be done with each."""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from zboxapi import guard, system

DiskState = str  # system | protected | blank | foreign | in-use

STORAGE_MOUNT_RE = re.compile(r"^(?P<root>.+)/(?P<name>STORAGE\d{2,3})$")


class PartitionView(BaseModel):
    name: str
    path: str
    size_bytes: int
    fstype: str | None
    label: str | None
    uuid: str | None
    mountpoint: str | None


class DiskView(BaseModel):
    name: str
    path: str
    size_bytes: int
    model: str | None
    serial: str | None
    pttype: str | None
    state: DiskState
    reason: str
    partitions: list[PartitionView]
    storage: str | None


def storage_name_of(node: system.BlockNode) -> str | None:
    """STORAGEnn if this node is mounted at <filer_root>/STORAGEnn."""
    if not node.mountpoint:
        return None
    m = STORAGE_MOUNT_RE.match(node.mountpoint)
    if m and m.group("root") == guard.filer_root():
        return m.group("name")
    return None


def classify(
    disk: system.BlockNode, ps: guard.ProtectedSet
) -> tuple[DiskState, str, str | None]:
    """(state, reason, storage) for one disk, from its subtree."""
    for node in disk.walk():
        if guard.is_system_node(node):
            return (
                "system",
                f"{disk.name} is the system disk ({node.mountpoint or 'swap'})",
                None,
            )
    if disk.name in ps.devices:
        return "protected", ps.reasons[disk.name], _storage_in(disk)
    if storage := _storage_in(disk):
        return "in-use", f"{disk.name} backs {storage}", storage
    if not disk.children and not disk.pttype and not disk.fstype:
        return (
            "blank",
            f"{disk.name} has no partition table and no filesystem signature",
            None,
        )
    found = [f"{n.pttype} partition table" for n in (disk,) if n.pttype]
    found += [f"{n.fstype} signature on {n.name}" for n in disk.walk() if n.fstype]
    return "foreign", f"{disk.name} is not blank: " + ", ".join(found), None


def _storage_in(disk: system.BlockNode) -> str | None:
    for node in disk.walk():
        if name := storage_name_of(node):
            return name
    return None


def disk_view(disk: system.BlockNode, ps: guard.ProtectedSet) -> DiskView:
    state, reason, storage = classify(disk, ps)
    return DiskView(
        name=disk.name,
        path=disk.path,
        size_bytes=disk.size,
        model=disk.model,
        serial=disk.serial,
        pttype=disk.pttype,
        state=state,
        reason=reason,
        storage=storage,
        partitions=[
            PartitionView(
                name=p.name,
                path=p.path,
                size_bytes=p.size,
                fstype=p.fstype,
                label=p.label,
                uuid=p.uuid,
                mountpoint=p.mountpoint,
            )
            for p in disk.children
            if p.type == "part"
        ],
    )


def inventory() -> list[DiskView]:
    nodes = system.block_devices()
    ps = guard.protected_set(nodes)
    return [disk_view(d, ps) for d in nodes if d.type == "disk"]


# API Router
disk_router = APIRouter(prefix="/disk", tags=["disk"])


@disk_router.get("", response_model=list[DiskView])
def disk_get_all() -> list[DiskView]:
    """Every disk with its state"""
    try:
        return inventory()
    except system.CommandError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(e)) from e


@disk_router.get("/{name}", response_model=DiskView)
def disk_get(name: str) -> DiskView:
    """One disk"""
    for disk in inventory():
        if disk.name == name:
            return disk
    raise HTTPException(status.HTTP_404_NOT_FOUND, f"Disk {name} not found")


# ── rescan ───────────────────────────────────────────────────────────────────────────


class ResizedDisk(BaseModel):
    disk: str
    before_bytes: int
    after_bytes: int
    storage: str | None


class RescanResult(BaseModel):
    new: list[str]
    resized: list[ResizedDisk]


def find_disk(name: str, nodes: list[system.BlockNode]) -> system.BlockNode | None:
    for disk in nodes:
        if disk.type == "disk" and disk.name == name:
            return disk
    return None


def rescan() -> RescanResult:
    """SCSI host scan for new disks, then a size rescan of every disk."""
    before = {d.name: d for d in system.block_devices() if d.type == "disk"}

    for host_scan in sorted(system.SYS_SCSI_HOST.glob("host*/scan")):
        system.write_sysfs(host_scan, "- - -\n", source="disk_rescan")

    # A size rescan reads the new geometry from the hypervisor and changes nothing on
    # the disk, so every disk gets one, the protected and system ones included.
    for name in sorted(before):
        node = system.SYS_BLOCK / name / "device" / "rescan"
        if node.exists():
            system.write_sysfs(node, "1\n", source="disk_rescan")

    after = {d.name: d for d in system.block_devices() if d.type == "disk"}
    return RescanResult(
        new=sorted(set(after) - set(before)),
        resized=[
            ResizedDisk(
                disk=name,
                before_bytes=before[name].size,
                after_bytes=after[name].size,
                storage=_storage_in(after[name]),
            )
            for name in sorted(before)
            if name in after and after[name].size != before[name].size
        ],
    )


@disk_router.post("/rescan", response_model=RescanResult)
def disk_rescan() -> RescanResult:
    """Detect new disks and size changes"""
    try:
        with system.storage_lock():
            return rescan()
    except (system.CommandError, OSError) as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(e)) from e


# ── detach ───────────────────────────────────────────────────────────────────────────


class DetachResult(BaseModel):
    disk: str
    serial: str | None
    detached: bool
    message: str


@disk_router.post("/{name}/detach", response_model=DetachResult)
def disk_detach(name: str) -> DetachResult:
    """Tell the kernel to forget a disk that is no longer in use, so it can be removed
    from the VM cleanly. Nothing on the disk is touched."""
    nodes = system.block_devices()
    ps = guard.protected_set(nodes)
    disk = find_disk(name, nodes)
    if disk is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Disk {name} not found")
    state, reason, storage = classify(disk, ps)
    if state in ("protected", "system"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, reason)
    mounted = [n.mountpoint for n in disk.walk() if n.mountpoint]
    if mounted:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{name} has a mounted filesystem ({', '.join(mounted)})"
            + (f"; remove {storage} first" if storage else ""),
        )
    node = system.SYS_BLOCK / name / "device" / "delete"
    if not node.exists():
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{name} cannot be detached: no {node}"
        )
    with system.storage_lock():
        system.write_sysfs(node, "1\n", source="disk_detach")
    gone = find_disk(name, system.block_devices()) is None
    return DetachResult(
        disk=name,
        serial=disk.serial,
        detached=gone,
        message=f"{name} removed from the kernel; the virtual disk can now be removed "
        "from the VM"
        if gone
        else f"{name} is still present after the delete request",
    )
