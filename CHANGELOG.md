# Changelog

Notable changes to zboxapi, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): `0.2.0` is the version in
`pyproject.toml`, the package on PyPI, and the git tag `v0.2.0`.

Entries describe what changed for the person running the API on a zbox or calling it: endpoints,
validation, status codes, configuration, installation. The commit history has the reasoning.

**Cutting a release.** Changes land under `[Unreleased]` as they are made. Then
`python3 tools/release.py X.Y.Z --push` (or `just release X.Y.Z`) does the rest: `[Unreleased]`
becomes `[X.Y.Z] — date`, the version moves in `pyproject.toml` and `uv.lock`, the tests run, the
commit is tagged `vX.Y.Z` and pushed, and the tag publishes this file's section as the GitHub
release note, with the PyPI link and install commands above it, then publishes the package to
PyPI (`.github/workflows/release.yml`, `tools/release_notes.py`). The script refuses a dirty tree,
an empty `[Unreleased]` (`--from-commits` fills it from the commits), a version not above the
last tag, a failing suite, and any string from the local `.release-denylist`; `--check` runs the
same rules, and CI runs it on every push. Preview a note with `python3 tools/release_notes.py X.Y.Z`.

## [Unreleased]

### Added
- **Disks, storages and NFS exports on zcore**: three new routers for the filer VM.
  - `/disk` lists every block device with a live state (`system`, `protected`, `blank`,
    `foreign`, `in-use`); `POST /disk/rescan` detects disks attached since boot and size
    changes; `POST /disk/{name}/detach` makes the kernel forget a disk nothing is mounted
    from, so it can be removed from the VM cleanly.
  - `/storage` lists the filesystems mounted at `/FILER/STORAGEnn` with layout, sizes in
    bytes (`size_bytes`, `used_bytes`, `available_bytes`) and top-level folders.
    `POST /storage` turns a blank disk into a mounted storage: GPT with one partition via
    sfdisk, optional one-VG-per-disk LVM, ext4, a systemd mount unit per storage ordered
    before nfs-server; `name` is optional and defaults to the next free number.
    `POST /storage/adopt` mounts an existing ext4 the same way without formatting.
    `POST /storage/{name}/grow` extends partition, PV, LV and filesystem online after a
    vSphere resize and is a no-op when nothing grew. `DELETE /storage/{name}` unmounts a
    storage that has no exports and leaves the filesystem and disk intact. A disk with
    anything on it is never formatted; there is no force flag for that.
  - Folders: `POST /storage/{name}/{folder}` creates one with an owner (`user:group`) and
    an octal mode, defaulting to the config; `PUT` applies chown and/or chmod, recursively
    on request; `DELETE` removes it when empty, or with everything in it when
    `?force=true` is passed; an exported folder is refused either way until its export is
    removed.
  - `/nfs` manages exports as a path, a list of clients (IPv4 address, IPv4 CIDR or `*`)
    and one options string per export, validated against an allowlist and defaulting to
    `rw,no_subtree_check,no_root_squash`. `POST /nfs` creates the folder when missing;
    `PUT /nfs/{storage}/{folder}` creates (201) or replaces (200) and is safe to repeat;
    `POST .../client` and `DELETE .../client/{client}` add and remove one client, the last
    removal removing the export; `DELETE /nfs/{storage}/{folder}` stops exporting and
    always keeps the folder and its data. Only `/etc/exports.d/zboxapi.exports` is written,
    replaced atomically, then `exportfs -ra`; the lines of `/etc/exports` are listed as
    owner `system` and never modified. `GET /nfs/status` reports the nfs-server state,
    versions, threads, exports served versus in the files, and the connected clients.
- **Guard rail.** NFS-01, `/FILER/STORAGE01` and the whole disk behind it are never
  modified, nor is the system disk; the one exception is growing, which only adds space.
  The protected set is computed on every request from the live mount, with STORAGE01 and
  NFS-01 as a floor the config cannot remove, and enforced three times: every mutating
  endpoint answers 403, the single command runner in `system.py` refuses any command
  naming a protected device except the exact grow shapes and audits every command to
  `/var/log/zboxapi-storage.log`, and the file writers refuse a protected path. Other
  folders and exports on STORAGE01 are ordinary.
- **Operations as steps.** Create, adopt, grow and delete answer with the storage `name`
  and named steps (`step`, `target`, `detail`, `status`, `exit_code`). `?dry_run=true`
  returns the plan with nothing run, `?verbose=true` adds each command and its output. A
  failed step rolls back what was done, in reverse, and the 500 lists both.
- **`GET /audit`**: the storage and nfs audit log, newest first, over the API.
- **Masquerade option on VLAN interfaces.** `POST /vlan` takes `masquerade: true` and
  `PUT /vlan/{id}/masquerade` toggles it: one nftables rule per VLAN in
  `/etc/nftables.d/zboxapi-masquerade.nft`, source-translating traffic that leaves on the
  management interface, so a VLAN scoped to the zPod can reach out without being routed from
  outside. Off by default; system VLANs refused; `masquerade` in every VLAN response is read
  from the live table. The rule follows a gateway change and goes before the interface on
  delete. Without `nft`, reads work and enabling answers 400.
- **Config sections `[storage]`, `[nfs]` and `[masquerade]`** in `/etc/zboxapi.conf`, every
  key optional; the existing file needs no change.
- **What zcore needs**: `lvm2` for `lvm: true` (400 until installed, raw works), and for
  masquerade rules to survive a reboot an `/etc/nftables.conf` that includes
  `/etc/nftables.d/*.nft` with `nftables.service` enabled. Both are packer-zcore changes;
  everything else is in the appliance already.

### Changed
- **VLAN overlap check covers the whole host.** A new or updated VLAN gateway may not overlap
  any network already present: the other VLANs, and every IPv4 address on any interface,
  `eth1` itself and `eth0` included (`10.10.20.64/28` inside `eth1.1000`'s `10.10.20.0/24`,
  or a VLAN inside `eth1`'s own subnet, both answer 400). The message names the conflicting
  VLAN or interface and its address instead of two normalised networks.

## [0.1.1] — 2026-10-04

### Fixed
- **PyPI project page links.** The README now uses absolute GitHub URLs, so the links to
  `DOC_DNS.md`, `DOC_VLAN.md`, the changelog and the release guide work on pypi.org instead
  of resolving to pages under the PyPI project; `[project.urls]` adds Homepage, Repository,
  Changelog, Documentation and Issues to the PyPI sidebar.

### Changed
- **Python 3.14 only.** `requires-python` is `>=3.14`; older interpreters are no longer
  supported or tested, since every zbox install is controlled. Install with
  `uv tool install zboxapi`, which fetches a managed 3.14 where the system Python is older.

## [0.1.0] — 2026-10-04

### Added
- **Releases follow the shared zPodFactory standard.** `tools/release.py` cuts a version
  (changelog heading, `pyproject.toml` and `uv.lock` bump, tests, commit, tag, push) and
  `tools/release_notes.py` publishes the changelog section as the GitHub release note.
  `.github/workflows/release.yml` runs it on every tag, then builds the wheel and sdist,
  publishes them to PyPI with `uv publish` and attaches them to the release.
  `.github/workflows/checks.yml` runs the release rules and the test suite on every push.
  See `tools/README.md`.
- **Unit tests**: pytest suite covering hostname validation, hosts-file handling,
  VLAN configuration/validation, every `/dns` and `/vlan` endpoint, authentication and
  OpenAPI operation IDs. System paths and commands are faked, so the tests run anywhere.
- **Python 3.14 support**: tested on Python 3.13 and 3.14; classifiers list 3.10 to 3.14.

### Changed
- **Build tooling**: migrated from Poetry to [uv](https://docs.astral.sh/uv/) with a
  PEP 621 `pyproject.toml`, the `uv_build` backend and `uv.lock`. `justfile` recipes now
  use `uv` and include `test`, `lint` and `format`.
- **Dependencies**: FastAPI, Pydantic and uvicorn upgraded to current releases
  (Pydantic 2.12+ is required for Python 3.14). `ipython` moved to the dev group.
- **Hostname validation**: fully qualified names such as `esx01.lab.local` are now
  accepted. Total length is limited to 253 characters and each label to 63, labels may
  not start or end with a hyphen, and error messages name the offending label.
- **Password lookup**: the zPod password is resolved at application startup (lifespan)
  and cached, instead of at module import. Behaviour for the systemd service is unchanged.
- **Operation IDs**: generated through FastAPI's `generate_unique_id_function`; the
  previous post-hoc rewrite was a no-op on FastAPI 0.142+.
- **Version string**: `zboxapi.__version__` is read from package metadata, so only
  `pyproject.toml` needs bumping.

### Fixed
- **VLAN create/update when a system VLAN interface has no address**: the overlap check
  tried to parse the `system-default` / `system-zpod` placeholder as a network and
  rejected every request with a misleading "Network overlap detected" error. Placeholders
  are now skipped.
- **403 for system VLANs on update and delete**: `PUT /vlan/{id}` and `DELETE /vlan/{id}`
  returned 500 for system VLANs; they now return 403 like `enable` and `disable`, as
  documented.
- **Config paths**: the hosts file, `/etc/zboxapi.conf` and `/etc/network/interfaces.d`
  are module-level constants (`HOSTS_FILE`, `CONFIG_FILE`, `INTERFACES_DIR`), making them
  overridable in tests.

## [0.0.7] — 2025-07-07

### Added
- **VLAN Management API**: Complete VLAN interface management system
  - Create, read, update, and delete VLAN interfaces via API
  - Automatic network configuration management
  - System VLAN protection (default: 10,20,30 and zPod: 64,128,192)
  - Network overlap detection and validation
  - Individual configuration files in `/etc/network/interfaces.d/`
  - Enable/disable VLAN interfaces via API

### Changed
- **Documentation Updates**:
  - Updated README.md with accurate configuration format and authentication details

### Fixed
- **Code Quality**:
  - Replaced deprecated `List` type annotations with built-in `list`
  - Added proper exception chaining with `from e` syntax
  - Removed unused imports (`os`, `IO`)
- **Exception Handling**: Fixed all exception handling to use proper chaining
- **Type Annotations**: Updated to use modern Python type annotations (Python 3.9+)

### Removed
- **Unused Imports**: Cleaned up unused `os` and `IO` imports

## [0.0.6] — 2024-05-22

### Changed
- **Breaking**: the DNS record field `fqdn` is renamed `hostname` in request bodies,
  responses and the `/dns/{ip}/{hostname}` path.

## [0.0.5] — 2024-05-20

### Changed
- DNS endpoints refactored: records are addressed as `/dns/{ip}/{hostname}` for get, update
  and delete, and every mutating call returns the full record list.

## [0.0.4] — 2024-05-15

### Added
- `ZBOXAPI_ROOT_PATH` environment variable (and a commented `Environment=` line in
  `zboxapi.service`) so the API can sit behind a reverse proxy under a path prefix.

### Changed
- Listens on `127.0.0.1:8000` by default.
- Operation IDs simplified to `<tag>_<function>` for generated clients; schema names updated.
- Dependencies updated.

## [0.0.3] — 2024-05-10

### Changed
- README no longer recommends pyenv; `pipx install zboxapi` is the supported install.

## [0.0.2] — 2024-05-08

### Added
- Initial release: a FastAPI service on the zbox VM that manages DNS records in `/etc/hosts`
  (list, get, add, update, delete) and reloads dnsmasq after each change. Every request
  carries the zPod password in the `access_token` header; the password is read from the
  VMware guest OVF environment.
