"""Storages: filesystems mounted at <filer_root>/STORAGEnn, raw or LVM, and folders."""

from __future__ import annotations

import grp
import os
import pwd
import re
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, status
from pydantic import AfterValidator, BaseModel, Field
from pydantic_core import PydanticCustomError

from zboxapi import config, guard, system
from zboxapi.disk import storage_name_of


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
    folders: int


class FolderView(BaseModel):
    name: str
    path: str
    exported: bool
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
        folders=len(folders_in(node.mountpoint or "")),
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


def folder_views(storage: StorageView) -> list[FolderView]:
    from zboxapi.nfs import export_paths

    paths = export_paths()
    out = []
    for folder in folders_in(storage.mountpoint):
        st = folder.stat()
        try:
            import grp
            import pwd

            owner = (
                f"{pwd.getpwuid(st.st_uid).pw_name}:{grp.getgrgid(st.st_gid).gr_name}"
            )
        except KeyError, ImportError:
            owner = f"{st.st_uid}:{st.st_gid}"
        out.append(
            FolderView(
                name=folder.name,
                path=str(folder),
                exported=str(folder) in paths,
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


@storage_router.get("/{name}/folder", response_model=list[FolderView])
def storage_folders(name: str) -> list[FolderView]:
    """Top-level folders of a storage"""
    return folder_views(get_storage(name))


# ── folders: create, chown/chmod, delete ─────────────────────────────────────────────

FOLDER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
OWNER_RE = re.compile(r"^[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$")
MODE_RE = re.compile(r"^[0-7]{3,4}$")


def validate_folder_name(value: str) -> str:
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
    """A new top-level folder. Owner and mode default to the [nfs] config values."""

    name: FOLDER_NAME
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
    for view in folder_views(storage):
        if view.name == name:
            return view
    raise HTTPException(status.HTTP_404_NOT_FOUND, f"Folder {name} not found")


@storage_router.post("/{name}/folder", response_model=FolderView)
def storage_folder_create(name: str, folder_in: FolderCreate) -> FolderView:
    """Create a top-level folder on a storage"""
    storage, path = protected_or_404(name, folder_in.name)
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
    return folder_view_of(storage, folder_in.name)


@storage_router.put("/{name}/folder/{folder}", response_model=FolderView)
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


@storage_router.delete("/{name}/folder/{folder}")
def storage_folder_delete(name: str, folder: FOLDER_NAME) -> dict:
    """Delete an empty, unexported folder"""
    from zboxapi.nfs import export_paths

    storage, path = protected_or_404(name, folder)
    with system.storage_lock():
        if not path.is_dir():
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Folder {folder} not found")
        if str(path) in export_paths():
            raise HTTPException(
                status.HTTP_409_CONFLICT, f"{path} is exported; delete the export first"
            )
        entries = sum(1 for _ in path.iterdir())
        if entries:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"{path} is not empty ({entries} entr{'y' if entries == 1 else 'ies'})",
            )
        path.rmdir()
        system.audit(["rmdir", str(path)], 0, "folder_delete")
    return {"message": f"Folder {path} deleted"}
