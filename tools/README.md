# Releasing

Two scripts, standard library only, the same in every zPodFactory repository. What differs per
repository is the configuration block at the top of each one.

| Script | Does |
|---|---|
| `release.py` | cuts a version: changelog heading, version bump (`pyproject.toml` and `uv.lock`), tests, commit, tag, push. Also `--check` and `--draft`. |
| `release_notes.py` | turns a version's `CHANGELOG.md` section into the GitHub release note. Run by the workflow. |

## Release in one command

You committed a few changes. Now:

```
python3 tools/release.py 0.2.0 --push --from-commits
```

- fills `[Unreleased]` in `CHANGELOG.md` from the commits since the last tag (subjects become the
  entries, grouped Added / Changed / Fixed / Removed; docs and version-bump commits are left out)
- turns `[Unreleased]` into `## [0.2.0] — <today>` and opens a fresh empty `[Unreleased]`
- sets the version in `pyproject.toml` and in the project's own entry in `uv.lock`
- runs `uv run --locked pytest -q`; a failing suite restores the files and releases nothing
- commits `Release 0.2.0`, tags `v0.2.0`, pushes `main` and the tag

GitHub then runs `.github/workflows/release.yml` on the tag: the same checks, the `[0.2.0]`
section is published as the release note and marked latest, then the wheel and sdist are built
with `uv build`, published to PyPI with `uv publish`, and attached to the release. About two
minutes. `just release 0.2.0` is the same command.

Add `--dry-run` to see the section and the plan without changing anything.

## Release when you want to write the entries yourself

```
python3 tools/release.py --draft --write      # the commit candidates, written under [Unreleased]
$EDITOR CHANGELOG.md                          # reword, delete what nobody needs
git commit -am "Changelog for 0.2.0"
python3 tools/release.py 0.2.0 --push
```

`--draft` alone only prints the candidates. Or skip the draft and write the entries as you go:
every change gets a line under `[Unreleased]`, and the cut needs nothing else.

## PyPI

The workflow publishes with `uv publish`. It uses, in this order:

1. the repository secret `PYPI_API_TOKEN`, when it is set (a PyPI API token scoped to the
   `zboxapi` project);
2. otherwise [trusted publishing](https://docs.pypi.org/trusted-publishers/): on pypi.org,
   project `zboxapi`, *Publishing*, add a GitHub publisher with owner `zPodFactory`, repository
   `zboxapi`, workflow `release.yml`, environment `pypi`. No secret to rotate.

Either one is a one-time setup. Without both, the `pypi` job fails and the GitHub release
still exists with its notes; set one up and re-run the job. `just publish` uploads a local
build with `uv publish` for the rare case where the workflow cannot (it needs
`UV_PUBLISH_TOKEN` in the environment).

## What stops a release

`release.py` refuses, before changing anything:

- a working tree that is not clean, or a branch other than `main`
- an empty `[Unreleased]` (nothing to say is not a release; `--from-commits` fills it)
- a version that is not above the newest tag, or that is not `X.Y.Z`
- a tracked `.env`, `*.log`, `docs/` or `runs/` file, or any other file that must stay local
- any string from `.release-denylist` in the tree or in the commits since the last tag. That file
  is local and git-ignored: names that must never enter the history.
- a failing test suite

`python3 tools/release.py --check` runs the rules that must hold between releases too: the shipped
version equals the newest changelog section, every tag has a section, nothing local is tracked.
`.github/workflows/checks.yml` runs it on every push, next to the test suite.

## Fixing a release note after the fact

Edit the section in `CHANGELOG.md`, commit, push. Then on GitHub: Actions, release, Run workflow,
version `0.2.0`. The release is updated in place; the tag never moves and nothing is re-published
to PyPI. A blank version republishes every tag, which is also how releases are backfilled for old
tags.

Never tag by hand, never edit a release in GitHub's editor: the file is the source, the release is a
copy.

## The configuration block

At the top of `release.py`:

| Setting | Meaning |
|---|---|
| `PROJECT` | name used in the tag message |
| `VERSION_FILE`, `VERSION_PATTERN` | where the shipped version is, and the regex (one group) that finds it |
| `VERSION_SHAPE` | `\d+\.\d+\.\d+` for the CLIs and packages, `\d+\.\d+(\.\d+)?` for packer |
| `VERSION_IN_FILE` | what is written into `VERSION_FILE`: `{version}`, or `{major_minor}` for packer |
| `REQUIRED_FILES` | files that must exist before a cut, e.g. `zbox-{major_minor}.json` |
| `ALSO_UPDATE` | other files carrying the version: here the `zboxapi` entry in `uv.lock` |
| `TEST_COMMAND` | run before the commit; `()` when there is no suite |
| `MUST_STAY_LOCAL` | regex for files that must never be tracked |

At the top of `release_notes.py`: `facts(version)`, markdown placed above the section. The PyPI
page and the install commands here; the ISO, its checksum, the OVA link and the build command for
a packer appliance.
