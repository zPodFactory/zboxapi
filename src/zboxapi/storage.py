"""Storages: filesystems mounted at <filer_root>/STORAGEnn, raw or LVM, and folders."""

from __future__ import annotations

import grp
import os
import pwd
import re
import shlex
import shutil
from pathlib import Path
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import AfterValidator, BaseModel, Field
from pydantic_core import PydanticCustomError

from zboxapi import config, guard, ops, system
from zboxapi.disk import storage_name_of
from zboxapi.ops import Step


class StorageView(BaseModel):
    name: str
    mountpoint: str
    disk: str
    device: str
    layout: str  # raw | lvm
    vg: str | None
    lv: str | None
    fstype: str | None
    uuid: str | None
    size: int
    used: int
    avail: int
    size_human: str
    used_human: str
    avail_human: str
    protected: bool
    managed: bool
    exports: int
    folders: list[FolderView]


class FolderView(BaseModel):
    name: str
    path: str
    exported: bool
    protected: bool
    empty: bool
    mode: str
    owner: str


def mount_unit_dir() -> Path:
    return Path(config.get("storage", "mount_unit_dir"))


def systemd_escape_path(path: str) -> str:
    """`/FILER/STORAGE02` -> `FILER-STORAGE02`, the way systemd-escape --path does."""
    out = []
    for ch in path.strip("/"):
        if ch == "/":
            out.append("-")
        elif ch.isalnum() or ch in "_.:":
            out.append(ch)
        else:
            out.append(f"\\x{ord(ch):02x}")
    return "".join(out) or "-"


def mountpoint_of(name: str) -> str:
    return f"{guard.filer_root()}/{name}"


def mount_unit_path(name: str) -> Path:
    return mount_unit_dir() / f"{systemd_escape_path(mountpoint_of(name))}.mount"


def usage(mountpoint: str) -> tuple[int, int, int]:
    """(size, used, avail) in bytes, as df reports them."""
    try:
        st = os.statvfs(mountpoint)
    except OSError:
        return 0, 0, 0
    size = st.f_frsize * st.f_blocks
    avail = st.f_frsize * st.f_bavail
    used = st.f_frsize * (st.f_blocks - st.f_bfree)
    return size, used, avail


def folders_in(mountpoint: str) -> list[Path]:
    try:
        return sorted(p for p in Path(mountpoint).iterdir() if p.is_dir())
    except OSError:
        return []


def storage_view(
    node: system.BlockNode, ps: guard.ProtectedSet, export_paths: set[str]
) -> StorageView:
    name = storage_name_of(node) or ""
    size, used, avail = usage(node.mountpoint or "")
    return StorageView(
        folders=folder_views(node.mountpoint or "", ps, export_paths),
        name=name,
        mountpoint=node.mountpoint or "",
        disk=node.disk.name,
        device=node.path,
        layout="lvm" if node.type == "lvm" else "raw",
        vg=node.vg,
        lv=node.lv,
        fstype=node.fstype,
        uuid=node.uuid,
        size=size,
        used=used,
        avail=avail,
        size_human=system.human_size(size),
        used_human=system.human_size(used),
        avail_human=system.human_size(avail),
        protected=name in ps.storages,
        managed=mount_unit_path(name).is_file(),
        exports=sum(1 for p in export_paths if p.startswith(node.mountpoint + "/")),
    )


def storages() -> list[StorageView]:
    from zboxapi.nfs import export_paths  # late import: nfs also imports storage

    nodes = system.block_devices()
    ps = guard.protected_set(nodes)
    paths = export_paths()
    views = [
        storage_view(node, ps, paths)
        for disk in nodes
        for node in disk.walk()
        if storage_name_of(node)
    ]
    return sorted(views, key=lambda s: s.name)


def get_storage(name: str) -> StorageView:
    for s in storages():
        if s.name == name:
            return s
    raise HTTPException(status.HTTP_404_NOT_FOUND, f"Storage {name} not found")


def folder_views(
    mountpoint: str, ps: guard.ProtectedSet, paths: set[str]
) -> list[FolderView]:
    out = []
    for folder in folders_in(mountpoint):
        st = folder.stat()
        try:
            owner = (
                f"{pwd.getpwuid(st.st_uid).pw_name}:{grp.getgrgid(st.st_gid).gr_name}"
            )
        except KeyError:
            owner = f"{st.st_uid}:{st.st_gid}"
        out.append(
            FolderView(
                name=folder.name,
                path=str(folder),
                exported=str(folder) in paths,
                protected=ps.reason_for(str(folder)) is not None,
                empty=not any(folder.iterdir()),
                mode=f"{st.st_mode & 0o7777:04o}",
                owner=owner,
            )
        )
    return out


# API Router
storage_router = APIRouter(prefix="/storage", tags=["storage"])


@storage_router.get("", response_model=list[StorageView])
def storage_get_all() -> list[StorageView]:
    """Every storage mounted under the filer root"""
    try:
        return storages()
    except system.CommandError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(e)) from e


@storage_router.get("/{name}", response_model=StorageView)
def storage_get(name: str) -> StorageView:
    """One storage"""
    return get_storage(name)


# ── storage lifecycle: create, adopt, grow, delete ───────────────────────────────────

STORAGE_NAME_RE = re.compile(r"^STORAGE\d{2,3}$")
LVM_TOOLS = ("pvcreate", "vgcreate", "lvcreate", "pvresize", "lvextend")


def validate_storage_name(value: str) -> str:
    if not STORAGE_NAME_RE.match(value):
        raise PydanticCustomError(
            "value_error",
            f"Invalid storage name '{value}': STORAGE followed by 2 or 3 digits",
        )
    return value


STORAGE_NAME = Annotated[str, AfterValidator(validate_storage_name)]


class StorageCreate(BaseModel):
    """A new storage on a blank disk."""

    disk: str = Field(..., description="disk name, e.g. sdc")
    lvm: bool = Field(False, description="one VG per disk (vg_storageNN) with one LV")
    name: STORAGE_NAME | None = Field(
        None, description="default: the next free STORAGEnn"
    )


class StorageAdopt(BaseModel):
    """Mount an existing, unmounted ext4 filesystem as a storage, without formatting."""

    device: str = Field(
        ..., description="sdd1, /dev/sdd1, vg_old/data or /dev/vg_old/data"
    )
    name: STORAGE_NAME | None = None


class OperationResult(BaseModel):
    operation: str
    dry_run: bool
    storage: StorageView | None = None
    steps: list[ops.StepView]
    rollback: list[ops.StepView] = []
    changed: bool | None = None
    before: dict[str, int] | None = None
    after: dict[str, int] | None = None
    disk_state: str | None = None


def lvm_available() -> bool:
    return all(shutil.which(tool) for tool in LVM_TOOLS)


def next_free_name(existing: set[str]) -> str:
    n = 2
    while f"STORAGE{n:02d}" in existing:
        n += 1
    return f"STORAGE{n:02d}"


def mount_unit_text(name: str, uuid: str, device: str) -> str:
    fstype = config.get("storage", "filesystem")
    options = config.get("storage", "mount_options")
    # local-fs.target, like an fstab entry, so the mount is in place before nfs-server
    # starts (it orders itself after local-fs.target); Before= makes it explicit.
    # Without both, exportfs skips the missing paths at boot: no exports until a reload.
    return (
        "[Unit]\n"
        f"Description=zboxapi storage {name} ({device})\n"
        "Before=nfs-server.service\n\n"
        "[Mount]\n"
        f"What=UUID={uuid}\n"
        f"Where={mountpoint_of(name)}\n"
        f"Type={fstype}\n"
        f"Options={options}\n\n"
        "[Install]\n"
        "WantedBy=local-fs.target\n"
    )


def http_from(e: Exception) -> HTTPException:
    if isinstance(e, guard.ProtectedError):
        return HTTPException(status.HTTP_403_FORBIDDEN, str(e))
    return HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(e))


def _mount_steps(plan: ops.Plan, name: str, uuid: str, device: str) -> None:
    """mountpoint, mount unit, mount: shared by create and adopt."""
    mountpoint = Path(mountpoint_of(name))
    unit = mount_unit_path(name)

    def mkdir():
        mountpoint.mkdir(mode=0o755, exist_ok=True)

    def write_unit():
        guard.assert_path_writable(str(unit))
        unit.write_text(mount_unit_text(name, uuid, device))

    plan.add(
        Step(
            "mountpoint",
            str(mountpoint),
            "create the mount point",
            action=mkdir,
            undo=lambda: mountpoint.rmdir(),
        )
    )
    plan.add(
        Step(
            "mount-unit",
            unit.name,
            f"systemd mount unit, What=UUID={uuid}",
            action=write_unit,
            undo=lambda: unit.unlink(),
        )
    )
    plan.add(
        Step(
            "daemon-reload",
            "systemd",
            "load the new unit",
            argv=["systemctl", "daemon-reload"],
        )
    )
    plan.add(
        Step(
            "mount",
            str(mountpoint),
            f"enable and start {unit.name}",
            argv=["systemctl", "enable", "--now", unit.name],
            undo_argv=["systemctl", "disable", "--now", unit.name],
        )
    )


def plan_create(body: StorageCreate) -> tuple[ops.Plan, str]:
    """Preconditions, then the plan. Raises HTTPException for anything that is wrong."""
    from zboxapi.disk import classify, find_disk

    nodes = system.block_devices()
    ps = guard.protected_set(nodes)
    disk = find_disk(body.disk, nodes)
    if disk is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Disk {body.disk} not found")
    state, reason, _ = classify(disk, ps)
    if state in ("protected", "system"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, reason)
    if state != "blank":
        raise HTTPException(status.HTTP_409_CONFLICT, reason)
    if body.lvm and not lvm_available():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "lvm2 is not installed on this host; use lvm: false or install lvm2",
        )

    existing = {s.name for s in storages()}
    name = body.name or next_free_name(existing)
    if name in existing:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{name} already exists")
    guard.assert_mutable(name, ps)
    mountpoint = Path(mountpoint_of(name))
    if mountpoint.exists() and any(mountpoint.iterdir()):
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{mountpoint} exists and is not empty"
        )
    if unit := mount_unit_path(name):
        if unit.exists():
            raise HTTPException(status.HTTP_409_CONFLICT, f"{unit} already exists")

    plan = ops.Plan("storage_create")
    disk_path, part = disk.path, f"{disk.path}1"
    vg = f"vg_{name.lower()}"
    device = f"/dev/{vg}/data" if body.lvm else part
    uuid = str(uuid4())
    fstype = config.get("storage", "filesystem")

    plan.add(
        Step(
            "partition",
            disk_path,
            "GPT label, one "
            + ("Linux LVM" if body.lvm else "Linux filesystem")
            + " partition",
            argv=["sfdisk", "--quiet", disk_path],
            stdin=f"label: gpt\n,,{'lvm' if body.lvm else 'linux'}\n",
            undo_argv=["wipefs", "-a", disk_path],
        )
    )
    plan.add(
        Step(
            "settle",
            disk_path,
            "wait for udev, re-read the partition table",
            argv=["udevadm", "settle"],
        )
    )
    plan.add(
        Step(
            "partx",
            disk_path,
            "tell the kernel about the new partition",
            argv=["partx", "-u", disk_path],
        )
    )
    if body.lvm:
        plan.add(
            Step(
                "pv",
                part,
                "physical volume",
                argv=["pvcreate", "-y", part],
                undo_argv=["pvremove", "-y", part],
            )
        )
        plan.add(
            Step(
                "vg",
                vg,
                f"volume group on {part}",
                argv=["vgcreate", vg, part],
                undo_argv=["vgremove", "-y", vg],
            )
        )
        plan.add(
            Step(
                "lv",
                device,
                "logical volume data, all free space",
                argv=["lvcreate", "-y", "-l", "100%FREE", "-n", "data", vg],
                undo_argv=["lvremove", "-y", f"{vg}/data"],
            )
        )
    plan.add(
        Step(
            "mkfs",
            device,
            f"{fstype}, label {name}",
            argv=[
                f"mkfs.{fstype}",
                "-F",
                "-L",
                name,
                "-U",
                uuid,
                *shlex.split(config.get("storage", "mkfs_options")),
                device,
            ],
            undo_argv=["wipefs", "-a", device],
        )
    )
    _mount_steps(plan, name, uuid, device)
    return plan, name


def plan_adopt(body: StorageAdopt) -> tuple[ops.Plan, str]:
    nodes = system.block_devices()
    ps = guard.protected_set(nodes)
    wanted = body.device
    if "/" in wanted and not wanted.startswith("/"):
        wanted = "/dev/" + wanted  # vg/lv
    node = next(
        (
            n
            for d in nodes
            for n in d.walk()
            if n.path == wanted
            or n.name == wanted
            or n.path == f"/dev/{wanted}"
            or (n.type == "lvm" and n.vg and f"/dev/{n.vg}/{n.lv}" == wanted)
        ),
        None,
    )
    if node is None or node.type == "disk":
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"Device {body.device} not found"
        )
    try:
        guard.assert_mutable(node.path, ps)
    except guard.ProtectedError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e)) from e
    fstype = config.get("storage", "filesystem")
    if node.fstype != fstype:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{node.path} has {node.fstype or 'no'} filesystem, expected {fstype}",
        )
    if node.mountpoint:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{node.path} is mounted at {node.mountpoint}"
        )
    if not node.uuid:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{node.path} has no UUID")

    existing = {s.name for s in storages()}
    name = body.name or next_free_name(existing)
    if name in existing:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{name} already exists")
    guard.assert_mutable(name, ps)
    mountpoint = Path(mountpoint_of(name))
    if mountpoint.exists() and any(mountpoint.iterdir()):
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{mountpoint} exists and is not empty"
        )
    if mount_unit_path(name).exists():
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{mount_unit_path(name)} already exists"
        )

    plan = ops.Plan("storage_adopt")
    device = f"/dev/{node.vg}/{node.lv}" if node.type == "lvm" else node.path
    _mount_steps(plan, name, node.uuid, device)
    return plan, name


def plan_grow(name: str) -> tuple[ops.Plan, system.BlockNode, dict[str, int]]:
    nodes = system.block_devices()
    ps = guard.protected_set(nodes)
    node = system.find_mounted(mountpoint_of(name), nodes)
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Storage {name} not found")
    # Growing is allowed on a protected storage: every step only adds space (see guard).
    assert ps is not None

    part = node.parent if node.type == "lvm" else node
    if part is None or part.type != "part" or part.parent is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{node.path} is not a partition on one disk"
        )
    disk = part.parent
    number = re.search(r"(\d+)$", part.name)
    if not number:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"cannot tell the partition number of {part.name}"
        )

    plan = ops.Plan("storage_grow")
    rescan_node = system.SYS_BLOCK / disk.name / "device" / "rescan"

    def rescan():
        if rescan_node.exists():
            system.write_sysfs(rescan_node, "1\n", source="storage_grow")
            return ops.DONE
        return ops.SKIPPED

    plan.add(
        Step(
            "rescan",
            disk.path,
            "re-read the disk size from the hypervisor",
            action=rescan,
        )
    )
    plan.add(
        Step(
            "growpart",
            part.path,
            "extend the partition to the end of the disk",
            argv=["growpart", disk.path, number.group(1)],
            nochange_rc=1,
        )
    )
    if node.type == "lvm":
        plan.add(
            Step(
                "pvresize",
                part.path,
                "extend the physical volume",
                argv=["pvresize", part.path],
            )
        )
        plan.add(
            Step(
                "lvextend",
                node.path,
                "extend the logical volume to all free space",
                argv=["lvextend", "-l", "+100%FREE", f"/dev/{node.vg}/{node.lv}"],
                nochange_rc=5,
            )
        )
    plan.add(
        Step(
            "resize2fs",
            node.path,
            "grow the filesystem online",
            argv=["resize2fs", node.path],
        )
    )
    return plan, node, sizes_of(node)


def sizes_of(node: system.BlockNode) -> dict[str, int]:
    part = node.parent if node.type == "lvm" else node
    out = {"disk": node.disk.size, "partition": part.size if part else 0}
    if node.type == "lvm":
        out["lv"] = node.size
    out["filesystem"] = usage(node.mountpoint or "")[0]
    return out


def plan_delete(name: str) -> ops.Plan:
    from zboxapi.nfs import export_paths

    storage = get_storage(name)
    try:
        guard.assert_mutable(name)
    except guard.ProtectedError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e)) from e
    exported = sorted(
        p for p in export_paths() if p.startswith(storage.mountpoint + "/")
    )
    if exported:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{name} has {len(exported)} export{'s' if len(exported) > 1 else ''}: "
            + ", ".join(exported),
        )
    unit = mount_unit_path(name)
    if not unit.is_file():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{name} was not mounted by this API (no {unit.name}); unmount it by hand",
        )
    plan = ops.Plan("storage_delete")
    mountpoint = Path(storage.mountpoint)
    plan.add(
        Step(
            "unmount",
            storage.mountpoint,
            f"disable and stop {unit.name}",
            argv=["systemctl", "disable", "--now", unit.name],
        )
    )
    plan.add(
        Step("mount-unit", unit.name, "remove the unit", action=lambda: unit.unlink())
    )
    plan.add(
        Step(
            "daemon-reload",
            "systemd",
            "forget the unit",
            argv=["systemctl", "daemon-reload"],
        )
    )
    plan.add(
        Step(
            "mountpoint",
            storage.mountpoint,
            "remove the empty mount point",
            action=lambda: mountpoint.rmdir(),
        )
    )
    return plan


def run_plan(
    plan: ops.Plan, *, dry_run: bool, verbose: bool, failure: str = "{error}"
) -> OperationResult:
    """`failure` formats the 500 message; `{error}` is the failing step's error."""
    if dry_run:
        return OperationResult(
            operation=plan.name, dry_run=True, steps=plan.views(verbose)
        )
    try:
        steps = plan.execute(verbose)
    except ops.OperationError as e:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            {
                "message": failure.format(error=e),
                "steps": [s.model_dump(exclude_none=True) for s in e.steps],
                "rollback": [s.model_dump(exclude_none=True) for s in e.rollback],
            },
        ) from e
    return OperationResult(operation=plan.name, dry_run=False, steps=steps)


@storage_router.post(
    "", response_model=OperationResult, response_model_exclude_none=True
)
def storage_create(
    body: StorageCreate, dry_run: bool = False, verbose: bool = False
) -> OperationResult:
    """Partition, (LVM), format and mount a blank disk as a new storage"""
    with system.storage_lock():
        plan, name = plan_create(body)
        result = run_plan(plan, dry_run=dry_run, verbose=verbose)
        if not dry_run:
            result.storage = get_storage(name)
    return result


@storage_router.post(
    "/adopt", response_model=OperationResult, response_model_exclude_none=True
)
def storage_adopt(
    body: StorageAdopt, dry_run: bool = False, verbose: bool = False
) -> OperationResult:
    """Mount an existing ext4 filesystem as a storage, without formatting"""
    with system.storage_lock():
        plan, name = plan_adopt(body)
        result = run_plan(plan, dry_run=dry_run, verbose=verbose)
        if not dry_run:
            result.storage = get_storage(name)
    return result


@storage_router.post(
    "/{name}/grow", response_model=OperationResult, response_model_exclude_none=True
)
def storage_grow(
    name: STORAGE_NAME, dry_run: bool = False, verbose: bool = False
) -> OperationResult:
    """Grow a storage after its virtual disk was enlarged"""
    with system.storage_lock():
        plan, node, before = plan_grow(name)
        result = run_plan(
            plan,
            dry_run=dry_run,
            verbose=verbose,
            failure=f"Cannot grow {name}: {{error}}. The data is untouched and the "
            "call can be retried",
        )
        result.before = before
        if not dry_run:
            after_node = system.find_mounted(mountpoint_of(name)) or node
            result.after = sizes_of(after_node)
            result.changed = any(
                result.after.get(k, 0) > before.get(k, 0) for k in ("partition", "lv")
            )
            result.storage = get_storage(name)
    return result


@storage_router.delete(
    "/{name}", response_model=OperationResult, response_model_exclude_none=True
)
def storage_delete(
    name: STORAGE_NAME, dry_run: bool = False, verbose: bool = False
) -> OperationResult:
    """Unmount a storage and forget its unit. Filesystem and disk are left intact."""
    from zboxapi.disk import classify, find_disk

    with system.storage_lock():
        storage = get_storage(name)
        plan = plan_delete(name)
        result = run_plan(plan, dry_run=dry_run, verbose=verbose)
        if not dry_run:
            nodes = system.block_devices()
            if disk := find_disk(storage.disk, nodes):
                result.disk_state = classify(disk, guard.protected_set(nodes))[0]
    return result


# ── folders: create, chown/chmod, delete ─────────────────────────────────────────────

FOLDER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
RESERVED_FOLDER_NAMES = frozenset(
    {"grow", "adopt", "folder"}
)  # sub-resources of /storage
OWNER_RE = re.compile(r"^[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$")
MODE_RE = re.compile(r"^[0-7]{3,4}$")


def validate_folder_name(value: str) -> str:
    if value.lower() in RESERVED_FOLDER_NAMES:
        raise PydanticCustomError(
            "value_error", f"'{value}' is a reserved name under /storage/{{name}}"
        )
    if value in (".", "..") or not FOLDER_NAME_RE.match(value):
        raise PydanticCustomError(
            "value_error",
            f"Invalid folder name '{value}': letters, digits, '.', '_' and '-' only, "
            "63 characters at most, no path separators",
        )
    return value


def validate_owner(value: str) -> str:
    """`user:group`, names or numeric ids, both resolvable on this host."""
    if not OWNER_RE.match(value):
        raise PydanticCustomError(
            "value_error", f"Invalid owner '{value}': use user:group"
        )
    user, group = value.split(":", 1)
    try:
        resolve_owner(value)
    except KeyError as e:
        raise PydanticCustomError(
            "value_error", f"Unknown {e.args[0]} in owner '{value}'"
        ) from e
    return f"{user}:{group}"


def validate_mode(value: str) -> str:
    if not MODE_RE.match(value):
        raise PydanticCustomError(
            "value_error", f"Invalid mode '{value}': octal such as 0777 or 755"
        )
    return value.zfill(4)


FOLDER_NAME = Annotated[str, AfterValidator(validate_folder_name)]
OWNER = Annotated[str, AfterValidator(validate_owner)]
MODE = Annotated[str, AfterValidator(validate_mode)]


class FolderCreate(BaseModel):
    """Owner and mode of a new folder; both default to the [nfs] config values."""

    owner: OWNER | None = Field(None, description="user:group, default from config")
    mode: MODE | None = Field(None, description="octal, default from config")


class FolderUpdate(BaseModel):
    """chown and/or chmod an existing folder."""

    owner: OWNER | None = None
    mode: MODE | None = None
    recursive: bool = Field(
        False, description="apply to everything below the folder as well"
    )


def resolve_owner(owner: str) -> tuple[int, int]:
    user, group = owner.split(":", 1)
    try:
        uid = int(user) if user.isdigit() else pwd.getpwnam(user).pw_uid
    except KeyError:
        raise KeyError("user") from None
    try:
        gid = int(group) if group.isdigit() else grp.getgrnam(group).gr_gid
    except KeyError:
        raise KeyError("group") from None
    return uid, gid


def default_owner() -> str:
    return config.get("nfs", "folder_owner")


def default_mode() -> str:
    return config.get("nfs", "folder_mode").zfill(4)


def apply_ownership(
    path: Path, owner: str | None, mode: str | None, *, recursive: bool, source: str
) -> list[Path]:
    """chown/chmod `path` (and its tree when recursive). Returns the paths touched."""
    targets = [path]
    if recursive:
        targets += sorted(p for p in path.rglob("*"))
    uid_gid = resolve_owner(owner) if owner else None
    bits = int(mode, 8) if mode else None
    for target in targets:
        if uid_gid is not None:
            os.chown(target, *uid_gid, follow_symlinks=False)
        if bits is not None and not target.is_symlink():
            os.chmod(target, bits)
    system.audit(
        [
            "folder-perms",
            str(path),
            f"owner={owner or '-'}",
            f"mode={mode or '-'}",
            f"recursive={recursive}",
            f"paths={len(targets)}",
        ],
        0,
        source,
    )
    return targets


def folder_path(storage: StorageView, folder: str) -> Path:
    return Path(storage.mountpoint) / folder


def protected_or_404(storage_name: str, folder: str) -> tuple[StorageView, Path]:
    """The storage and folder path, after the guard; existence is the caller's call."""
    storage = get_storage(storage_name)
    path = folder_path(storage, folder)
    try:
        guard.assert_mutable(str(path))
    except guard.ProtectedError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e)) from e
    return storage, path


def folder_view_of(storage: StorageView, name: str) -> FolderView:
    for view in get_storage(storage.name).folders:
        if view.name == name:
            return view
    raise HTTPException(status.HTTP_404_NOT_FOUND, f"Folder {name} not found")


@storage_router.post("/{name}/{folder}", response_model=FolderView)
def storage_folder_create(
    name: str, folder: FOLDER_NAME, folder_in: FolderCreate | None = None
) -> FolderView:
    """Create a top-level folder on a storage"""
    folder_in = folder_in or FolderCreate()
    storage, path = protected_or_404(name, folder)
    with system.storage_lock():
        if path.exists():
            raise HTTPException(status.HTTP_409_CONFLICT, f"{path} already exists")
        owner = folder_in.owner or default_owner()
        mode = folder_in.mode or default_mode()
        try:
            resolve_owner(owner)
        except KeyError as e:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Configured folder_owner '{owner}' has an unknown {e.args[0]}",
            ) from e
        path.mkdir(mode=0o700)
        try:
            apply_ownership(path, owner, mode, recursive=False, source="folder_create")
        except OSError as e:
            path.rmdir()
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                f"Failed to set ownership on {path}: {e}",
            ) from e
    return folder_view_of(storage, folder)


@storage_router.put("/{name}/{folder}", response_model=FolderView)
def storage_folder_update(
    name: str, folder: FOLDER_NAME, folder_in: FolderUpdate
) -> FolderView:
    """chown and/or chmod a folder"""
    storage, path = protected_or_404(name, folder)
    if folder_in.owner is None and folder_in.mode is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Give an owner, a mode, or both"
        )
    with system.storage_lock():
        if not path.is_dir():
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Folder {folder} not found")
        try:
            apply_ownership(
                path,
                folder_in.owner,
                folder_in.mode,
                recursive=folder_in.recursive,
                source="folder_update",
            )
        except OSError as e:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                f"Failed to change {path}: {e}",
            ) from e
    return folder_view_of(storage, folder)


class FolderDeleted(BaseModel):
    message: str
    path: str
    removed: int  # files and directories removed, the folder itself included
    forced: bool


def tree_size(path: Path) -> int:
    """How many files and directories a recursive delete would remove, root included."""
    return 1 + sum(1 for _ in path.rglob("*"))


@storage_router.delete("/{name}/{folder}", response_model=FolderDeleted)
def storage_folder_delete(
    name: str, folder: FOLDER_NAME, force: bool = False
) -> FolderDeleted:
    """Delete an unexported folder: empty, or with everything in it when force=true"""
    from zboxapi.nfs import export_paths

    storage, path = protected_or_404(name, folder)
    with system.storage_lock():
        if not path.is_dir():
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Folder {folder} not found")
        if str(path) in export_paths():
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"{path} is exported; delete the export first"
                + (" (force does not override this)" if force else ""),
            )
        entries = sum(1 for _ in path.iterdir())
        if entries and not force:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"{path} is not empty "
                f"({entries} entr{'y' if entries == 1 else 'ies'}); "
                "pass force=true to delete it with its contents",
            )
        removed = tree_size(path) if force else 1
        try:
            if force:
                shutil.rmtree(path)
            else:
                path.rmdir()
        except OSError as e:
            raise HTTPException(
                status.HTTP_500_INTERNAL_SERVER_ERROR, f"Failed to delete {path}: {e}"
            ) from e
        system.audit(
            ["rm", "-rf" if force else "-d", str(path), f"removed={removed}"],
            0,
            "folder_delete",
        )
    return FolderDeleted(
        message=f"Folder {path} deleted"
        + (f" with {removed - 1} entries" if force else ""),
        path=str(path),
        removed=removed,
        forced=force,
    )
