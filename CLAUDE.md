# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Project Overview

zboxapi is a FastAPI service that runs on the zPodFactory zbox VM (`127.0.0.1:8000`, as root,
through `zboxapi.service`). It manages DNS records in `/etc/hosts` with a dnsmasq reload
(`src/zboxapi/dns.py`) and VLAN interfaces under `/etc/network/interfaces.d/`
(`src/zboxapi/vlan.py`). Every request carries the zPod password in the `access_token` header;
`src/zboxapi/main.py` reads it from the VMware OVF environment at startup.

## Commands

```bash
uv sync                                  # .venv with the project and dev dependencies
uv run pytest -q                         # the suite; no root, /etc or network needed
uv run pytest --cov --cov-report=term-missing
uv run ruff check src tests && uv run ruff format --check src tests
just                                     # lists the same as recipes
```

The tests redirect `HOSTS_FILE`, `CONFIG_FILE` and `INTERFACES_DIR` to temp paths and replace
`subprocess.run`/`subprocess.call` with the fake in `tests/conftest.py`. Keep new system
interaction behind those module constants and `subprocess` so it stays testable.

## Releases

- Versions are SemVer: `pyproject.toml` `0.2.0` is tag `v0.2.0` is PyPI `0.2.0`.
- Every change gets a line under `[Unreleased]` in `CHANGELOG.md`: what changed for the person
  running or calling the API, and why in a clause.
- A release is one command: `python3 tools/release.py X.Y.Z --push` (`--dry-run` first, or
  `just release X.Y.Z`). The cut moves the heading, bumps `pyproject.toml` and `uv.lock`, runs
  the tests, commits, tags `vX.Y.Z`, pushes; the tag then publishes the section as the GitHub
  release and the package to PyPI through `.github/workflows/release.yml`.
- `python3 tools/release.py --check` is what CI runs on every push: shipped version equals the
  newest section, every tag has a section, nothing local is tracked. Keep the forbidden-string
  list in `.release-denylist` (git-ignored) for the names that must never enter the history.
- Never tag by hand, never edit a release on GitHub, never run `uv publish` by hand unless the
  workflow cannot: fix the changelog and re-run the workflow (`workflow_dispatch`, blank
  version republishes every tag's notes; PyPI is only ever published from a pushed tag).
