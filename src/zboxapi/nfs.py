"""NFS exports: /etc/exports (system, read-only) and the file this API manages."""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, status
from pydantic import AfterValidator, BaseModel, Field
from pydantic_core import PydanticCustomError

from zboxapi import config, guard, system
from zboxapi import storage as storage_mod
from zboxapi.storage import FOLDER_NAME, STORAGE_NAME

EXPORT_PATH_RE = re.compile(
    r"^(?P<root>/.+)/(?P<storage>STORAGE\d{2,3})/(?P<folder>[^/]+)$"
)


class ClientView(BaseModel):
    client: str
    options: str


class ExportView(BaseModel):
    path: str
    storage: str | None
    folder: str | None
    clients: list[ClientView]
    owner: str  # system | user-defined
    protected: bool
    active: bool
    folder_exists: bool


def system_exports_file() -> Path:
    return Path(config.get("nfs", "system_exports_file"))


def managed_exports_file() -> Path:
    return Path(config.get("nfs", "exports_file"))


# ── exports(5) parsing ───────────────────────────────────────────────────────────────


def parse_exports(text: str) -> dict[str, list[ClientView]]:
    """`/path client(opts) client2(opts)` lines, comments and continuations handled."""
    out: dict[str, list[ClientView]] = {}
    logical = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if line.endswith("\\"):
            logical += line[:-1] + " "
            continue
        logical += line
        tokens = logical.split()
        logical = ""
        if not tokens:
            continue
        path, entries = tokens[0], tokens[1:]
        clients = out.setdefault(path, [])
        for entry in entries:
            m = re.match(r"^([^(]*)(?:\((.*)\))?$", entry)
            client = (m.group(1) if m else entry) or "*"
            options = (m.group(2) if m else "") or ""
            clients.append(
                ClientView(client=_normalise_client(client), options=options)
            )
    return out


def _normalise_client(client: str) -> str:
    return "*" if client in ("*", "<world>", "") else client


def parse_exportfs_v(text: str) -> dict[str, list[ClientView]]:
    """`exportfs -v`: a path then its client(options), the client on its own line when
    the path is long."""
    out: dict[str, list[ClientView]] = {}
    current: str | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("/"):
            parts = line.split(None, 1)
            current = parts[0]
            out.setdefault(current, [])
            rest = parts[1].strip() if len(parts) > 1 else ""
        else:
            rest = line.strip()
        if rest and current:
            m = re.match(r"^([^(]*)(?:\((.*)\))?$", rest)
            out[current].append(
                ClientView(
                    client=_normalise_client(m.group(1) if m else rest),
                    options=(m.group(2) if m else "") or "",
                )
            )
    return out


def read_file(path: Path) -> dict[str, list[ClientView]]:
    try:
        return parse_exports(path.read_text())
    except OSError:
        return {}


def active_exports() -> dict[str, list[ClientView]]:
    result = system.query(["exportfs", "-v"], check=False)
    return parse_exportfs_v(result.stdout or "") if result.returncode == 0 else {}


def export_paths() -> set[str]:
    """Every exported path, system and managed, from the files."""
    return set(read_file(system_exports_file())) | set(
        read_file(managed_exports_file())
    )


def exports(ps: guard.ProtectedSet | None = None) -> list[ExportView]:
    ps = ps if ps is not None else guard.protected_set()
    active = active_exports()
    views: dict[str, ExportView] = {}
    for owner, path in (
        ("system", system_exports_file()),
        ("user-defined", managed_exports_file()),
    ):
        for export_path, clients in read_file(path).items():
            if export_path in views:
                continue  # the system file wins over a duplicate in the managed one
            m = EXPORT_PATH_RE.match(export_path)
            conventional = bool(m and m.group("root") == guard.filer_root())
            views[export_path] = ExportView(
                path=export_path,
                storage=m.group("storage") if conventional else None,
                folder=m.group("folder") if conventional else None,
                clients=clients,
                owner=owner,
                protected=export_path in ps.exports,
                active=export_path in active,
                folder_exists=Path(export_path).is_dir(),
            )
    return sorted(views.values(), key=lambda e: e.path)


def get_export(storage: str, folder: str) -> ExportView:
    path = f"{guard.filer_root()}/{storage}/{folder}"
    for export in exports():
        if export.path == path:
            return export
    raise HTTPException(status.HTTP_404_NOT_FOUND, f"Export {path} not found")


# API Router
nfs_router = APIRouter(prefix="/nfs", tags=["nfs"])


@nfs_router.get("", response_model=list[ExportView])
def nfs_get_all() -> list[ExportView]:
    """Every export, system and user-defined"""
    try:
        return exports()
    except system.CommandError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(e)) from e


@nfs_router.get("/{storage}/{folder}", response_model=ExportView)
def nfs_get(storage: str, folder: str) -> ExportView:
    """One export"""
    return get_export(storage, folder)


# ── exports CRUD ─────────────────────────────────────────────────────────────────────


def validate_client(value: str) -> str:
    """An IPv4 address, an IPv4 network in CIDR notation, or `*` for everyone."""
    value = value.strip()
    if value in ("*", "<world>"):
        return "*"
    try:
        if "/" in value:
            ipaddress.IPv4Network(value, strict=False)
        else:
            ipaddress.IPv4Address(value)
    except ValueError as e:
        raise PydanticCustomError(
            "value_error",
            f"Invalid client '{value}': an IPv4 address, an IPv4 network such as "
            "10.60.60.0/26, or * for everyone",
        ) from e
    return value


CLIENT = Annotated[str, AfterValidator(validate_client)]


def _unique(clients: list[str]) -> list[str]:
    seen = set(clients)
    if len(seen) != len(clients):
        raise PydanticCustomError("value_error", "Duplicate client in the list")
    return clients


CLIENTS = Annotated[list[CLIENT], Field(min_length=1), AfterValidator(_unique)]


class ExportCreate(BaseModel):
    storage: STORAGE_NAME
    folder: FOLDER_NAME
    clients: CLIENTS


class ExportUpdate(BaseModel):
    clients: CLIENTS


class ClientAdd(BaseModel):
    client: CLIENT


class ExportDeleted(BaseModel):
    message: str
    path: str
    folder_kept: bool = True


def export_options() -> str:
    return config.get("nfs", "export_options")


def write_managed(table: dict[str, list[str]]) -> None:
    """Rewrite the managed exports file atomically: temp file, fsync, rename."""
    path = managed_exports_file()
    options = export_options()
    lines = [
        f"{export_path} " + " ".join(f"{c}({options})" for c in clients)
        for export_path, clients in table.items()
        if clients
    ]
    text = "# Managed by zboxapi (/nfs). Change it through the API.\n" + "".join(
        line + "\n" for line in lines
    )
    guard.assert_path_writable(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
        tmp = Path(handle.name)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def managed_table() -> dict[str, list[str]]:
    return {
        p: [c.client for c in cs] for p, cs in read_file(managed_exports_file()).items()
    }


def reload_exports(source: str) -> None:
    system.run(["exportfs", "-ra"], source=source)


def export_path_of(storage: str, folder: str) -> str:
    return f"{guard.filer_root()}/{storage}/{folder}"


def mutable_export(storage: str, folder: str, *, must_exist: bool) -> str:
    """The export path, after the guard and the owner check. 404 when must_exist and
    the path is in neither file, 403 when it is protected or lives in /etc/exports."""
    path = export_path_of(storage, folder)
    try:
        guard.assert_mutable(path)
    except guard.ProtectedError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e)) from e
    if path in read_file(system_exports_file()):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"{path} is exported by {system_exports_file()} (owner system); "
            "this API only manages its own exports file",
        )
    if must_exist and path not in managed_table():
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Export {path} not found")
    return path


def mounted_storage(name: str) -> storage_mod.StorageView:
    try:
        return storage_mod.get_storage(name)
    except HTTPException as e:
        if e.status_code == status.HTTP_404_NOT_FOUND:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, f"Storage {name} is not mounted"
            ) from e
        raise


def ensure_folder(path: Path, source: str) -> bool:
    """Create the export folder with the configured owner and mode. True if created."""
    if path.is_dir():
        return False
    if path.exists():
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"{path} exists and is not a folder"
        )
    path.mkdir(mode=0o700)
    try:
        storage_mod.apply_ownership(
            path,
            storage_mod.default_owner(),
            storage_mod.default_mode(),
            recursive=False,
            source=source,
        )
    except (OSError, KeyError) as e:
        path.rmdir()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, f"Failed to create {path}: {e}"
        ) from e
    return True


def view_of(path: str) -> ExportView:
    for export in exports():
        if export.path == path:
            return export
    raise HTTPException(status.HTTP_404_NOT_FOUND, f"Export {path} not found")


@nfs_router.post("", response_model=ExportView)
def nfs_create(export_in: ExportCreate) -> ExportView:
    """Export a folder (created if missing) to a list of clients"""
    path = mutable_export(export_in.storage, export_in.folder, must_exist=False)
    with system.storage_lock():
        storage = mounted_storage(export_in.storage)
        table = managed_table()
        if path in table:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{path} is already exported")
        ensure_folder(Path(storage.mountpoint) / export_in.folder, "nfs_create")
        table[path] = list(export_in.clients)
        write_managed(table)
        system.audit(["export", path, *export_in.clients], 0, "nfs_create")
        reload_exports("nfs_create")
    return view_of(path)


@nfs_router.put("/{storage}/{folder}", response_model=ExportView)
def nfs_update(storage: str, folder: str, export_in: ExportUpdate) -> ExportView:
    """Replace the client list of an export"""
    path = mutable_export(storage, folder, must_exist=True)
    with system.storage_lock():
        table = managed_table()
        table[path] = list(export_in.clients)
        write_managed(table)
        system.audit(["export", path, *export_in.clients], 0, "nfs_update")
        reload_exports("nfs_update")
    return view_of(path)


@nfs_router.post("/{storage}/{folder}/client", response_model=ExportView)
def nfs_client_add(storage: str, folder: str, client_in: ClientAdd) -> ExportView:
    """Add one client to an export"""
    path = mutable_export(storage, folder, must_exist=True)
    with system.storage_lock():
        table = managed_table()
        if client_in.client in table[path]:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"{client_in.client} is already a client of {path}",
            )
        table[path].append(client_in.client)
        write_managed(table)
        system.audit(["export-client-add", path, client_in.client], 0, "nfs_client_add")
        reload_exports("nfs_client_add")
    return view_of(path)


@nfs_router.delete(
    "/{storage}/{folder}/client/{client:path}",
    response_model=ExportView | ExportDeleted,
)
def nfs_client_remove(storage: str, folder: str, client: str):
    """Remove one client; removing the last client removes the export"""
    path = mutable_export(storage, folder, must_exist=True)
    client = "*" if client in ("*", "<world>") else client
    with system.storage_lock():
        table = managed_table()
        if client not in table[path]:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, f"{client} is not a client of {path}"
            )
        table[path].remove(client)
        last = not table[path]
        if last:
            del table[path]
        write_managed(table)
        system.audit(["export-client-remove", path, client], 0, "nfs_client_remove")
        reload_exports("nfs_client_remove")
    if last:
        return ExportDeleted(
            message=f"{client} was the last client: {path} is no longer exported; "
            "the folder and its data stay",
            path=path,
        )
    return view_of(path)


@nfs_router.delete("/{storage}/{folder}", response_model=ExportDeleted)
def nfs_delete(storage: str, folder: str) -> ExportDeleted:
    """Stop exporting a folder. The folder and its data stay."""
    path = mutable_export(storage, folder, must_exist=True)
    with system.storage_lock():
        table = managed_table()
        del table[path]
        write_managed(table)
        system.audit(["unexport", path], 0, "nfs_delete")
        reload_exports("nfs_delete")
    return ExportDeleted(
        message=f"{path} is no longer exported; the folder and its data stay", path=path
    )
