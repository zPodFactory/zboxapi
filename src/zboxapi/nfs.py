"""NFS exports: /etc/exports (system, read-only) and the file this API manages."""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from zboxapi import config, guard, system

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
