"""NFS exports: /etc/exports (system, read-only) and the file this API manages."""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Response, status
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
    options: str  # what every client of this export gets
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
                options=clients[0].options if clients else "",
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


# ── server status ────────────────────────────────────────────────────────────────────

PROC_NFSD = Path("/proc/fs/nfsd")
RMTAB = Path("/var/lib/nfs/rmtab")


class NfsClientView(BaseModel):
    client: str  # address, or host:port for NFSv4
    path: (
        str | None
    )  # the mounted export (NFSv3 only; NFSv4 clients mount the pseudo root)
    version: str  # "3" (from rmtab/showmount) or "4.x" (from nfsd)


class NfsStatus(BaseModel):
    service: str  # active | inactive | failed | unknown
    enabled: bool
    versions: list[str]  # NFS versions the server serves, e.g. ["3", "4", "4.1", "4.2"]
    threads: int | None
    exports: int  # paths exportfs currently serves
    exports_in_files: int  # paths in /etc/exports plus the managed file
    inactive_exports: list[
        str
    ]  # in a file, not served (folder missing, or reload needed)
    clients: list[NfsClientView]


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def nfs_versions() -> list[str]:
    """`/proc/fs/nfsd/versions` reads like `-2 +3 +4 +4.1 +4.2`."""
    return [t[1:] for t in _read(PROC_NFSD / "versions").split() if t.startswith("+")]


def nfs_clients() -> list[NfsClientView]:
    out: list[NfsClientView] = []
    # NFSv3: rmtab, what showmount -a prints. Best effort: entries can be stale.
    result = system.query(["showmount", "-a", "--no-headers"], check=False)
    lines = (result.stdout or "").splitlines() if result.returncode == 0 else []
    if not lines:
        lines = [
            ln.split(":", 1)[0] + ":" + ln.split(":", 2)[1]
            for ln in _read(RMTAB).splitlines()
            if ln.count(":") >= 2
        ]
    for line in lines:
        host, _, path = line.strip().partition(":")
        if host:
            out.append(NfsClientView(client=host, path=path or None, version="3"))
    # NFSv4: one directory per client under /proc/fs/nfsd/clients, with an info file.
    for info in sorted((PROC_NFSD / "clients").glob("*/info")):
        fields = dict(ln.split(":", 1) for ln in _read(info).splitlines() if ":" in ln)
        address = fields.get("address", "").strip().strip('"')
        minor = fields.get("minor version", "").strip()
        if address:
            out.append(
                NfsClientView(
                    client=address, path=None, version=f"4.{minor}" if minor else "4"
                )
            )
    return out


def nfs_status() -> NfsStatus:
    active = system.query(["systemctl", "is-active", "nfs-server"], check=False)
    enabled = system.query(["systemctl", "is-enabled", "nfs-server"], check=False)
    live = active_exports()
    in_files = export_paths()
    threads = _read(PROC_NFSD / "threads").strip()
    return NfsStatus(
        service=(active.stdout or "unknown").strip() or "unknown",
        enabled=(enabled.stdout or "").strip() == "enabled",
        versions=nfs_versions(),
        threads=int(threads) if threads.isdigit() else None,
        exports=len(live),
        exports_in_files=len(in_files),
        inactive_exports=sorted(in_files - set(live)),
        clients=nfs_clients(),
    )


# API Router
nfs_router = APIRouter(prefix="/nfs", tags=["nfs"])


@nfs_router.get("/status", response_model=NfsStatus)
def nfs_get_status() -> NfsStatus:
    """The NFS server: service state, versions, threads, exports served, clients"""
    try:
        return nfs_status()
    except system.CommandError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(e)) from e


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

# exports(5) options this API accepts, and the pairs that cannot both be given
EXPORT_OPTION_FLAGS = frozenset(
    {
        "ro",
        "rw",
        "sync",
        "async",
        "root_squash",
        "no_root_squash",
        "all_squash",
        "no_all_squash",
        "subtree_check",
        "no_subtree_check",
        "secure",
        "insecure",
        "wdelay",
        "no_wdelay",
        "crossmnt",
        "hide",
        "nohide",
    }
)
EXPORT_OPTION_VALUES = {
    "sec": re.compile(r"^(sys|krb5|krb5i|krb5p)(:(sys|krb5|krb5i|krb5p))*$"),
    "anonuid": re.compile(r"^\d+$"),
    "anongid": re.compile(r"^\d+$"),
    "fsid": re.compile(r"^(\d+|root|[0-9a-fA-F-]{36})$"),
}
EXPORT_OPTION_CONFLICTS = (
    ("ro", "rw"),
    ("sync", "async"),
    ("root_squash", "no_root_squash"),
    ("all_squash", "no_all_squash"),
    ("subtree_check", "no_subtree_check"),
    ("secure", "insecure"),
    ("wdelay", "no_wdelay"),
    ("hide", "nohide"),
)


def validate_options(value: str) -> str:
    """A comma-separated exports(5) option string from the allowlist, normalised."""
    tokens = [t.strip() for t in value.split(",") if t.strip()]
    if not tokens:
        raise PydanticCustomError("value_error", "Export options cannot be empty")
    seen: list[str] = []
    for token in tokens:
        key, _, val = token.partition("=")
        if key in EXPORT_OPTION_FLAGS and not val:
            pass
        elif key in EXPORT_OPTION_VALUES and EXPORT_OPTION_VALUES[key].match(val):
            pass
        else:
            raise PydanticCustomError(
                "value_error",
                f"Unknown or malformed export option '{token}'; allowed: "
                + ", ".join(sorted(EXPORT_OPTION_FLAGS))
                + ", sec=, anonuid=, anongid=, fsid=",
            )
        if token in seen:
            raise PydanticCustomError(
                "value_error", f"Duplicate export option '{token}'"
            )
        seen.append(token)
    for a, b in EXPORT_OPTION_CONFLICTS:
        if a in seen and b in seen:
            raise PydanticCustomError(
                "value_error", f"Export options '{a}' and '{b}' cannot both be given"
            )
    return ",".join(seen)


OPTIONS = Annotated[str, AfterValidator(validate_options)]


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
    options: OPTIONS | None = Field(
        None, description="exports(5) options for every client; default from config"
    )


class ExportUpdate(BaseModel):
    clients: CLIENTS
    options: OPTIONS | None = Field(
        None, description="replace the options too; omitted keeps the current ones"
    )


class ClientAdd(BaseModel):
    client: CLIENT


class ExportDeleted(BaseModel):
    message: str
    path: str
    folder_kept: bool = True


def export_options() -> str:
    return config.get("nfs", "export_options")


class Managed(BaseModel):
    clients: list[str]
    options: str


def write_managed(table: dict[str, Managed]) -> None:
    """Rewrite the managed exports file atomically: temp file, fsync, rename."""
    path = managed_exports_file()
    lines = [
        f"{export_path} " + " ".join(f"{c}({entry.options})" for c in entry.clients)
        for export_path, entry in table.items()
        if entry.clients
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


def managed_table() -> dict[str, Managed]:
    return {
        p: Managed(
            clients=[c.client for c in cs],
            options=cs[0].options if cs else export_options(),
        )
        for p, cs in read_file(managed_exports_file()).items()
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
        options = export_in.options or export_options()
        table[path] = Managed(clients=list(export_in.clients), options=options)
        write_managed(table)
        system.audit(
            ["export", path, f"({options})", *export_in.clients], 0, "nfs_create"
        )
        reload_exports("nfs_create")
    return view_of(path)


@nfs_router.put("/{storage}/{folder}", response_model=ExportView)
def nfs_update(
    storage: STORAGE_NAME,
    folder: FOLDER_NAME,
    export_in: ExportUpdate,
    response: Response,
) -> ExportView:
    """Make the export exist with exactly these clients: created when missing (201),
    replaced otherwise (200). Safe to repeat."""
    path = mutable_export(storage, folder, must_exist=False)
    with system.storage_lock():
        table = managed_table()
        created = path not in table
        if created:
            mounted = mounted_storage(storage)
            ensure_folder(Path(mounted.mountpoint) / folder, "nfs_update")
        options = export_in.options or (
            table[path].options if not created else export_options()
        )
        table[path] = Managed(clients=list(export_in.clients), options=options)
        write_managed(table)
        system.audit(
            ["export", path, f"({options})", *export_in.clients], 0, "nfs_update"
        )
        reload_exports("nfs_update")
    if created:
        response.status_code = status.HTTP_201_CREATED
    return view_of(path)


@nfs_router.post("/{storage}/{folder}/client", response_model=ExportView)
def nfs_client_add(storage: str, folder: str, client_in: ClientAdd) -> ExportView:
    """Add one client to an export"""
    path = mutable_export(storage, folder, must_exist=True)
    with system.storage_lock():
        table = managed_table()
        if client_in.client in table[path].clients:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"{client_in.client} is already a client of {path}",
            )
        table[path].clients.append(client_in.client)
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
        if client not in table[path].clients:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, f"{client} is not a client of {path}"
            )
        table[path].clients.remove(client)
        last = not table[path].clients
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
