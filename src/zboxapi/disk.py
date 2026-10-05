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
    size: int
    size_human: str
    fstype: str | None
    label: str | None
    uuid: str | None
    mountpoint: str | None


class DiskView(BaseModel):
    name: str
    path: str
    size: int
    size_human: str
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
        size=disk.size,
        size_human=system.human_size(disk.size),
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
                size=p.size,
                size_human=system.human_size(p.size),
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
