set dotenv-load
set positional-arguments

@_default:
  just --list --list-heading $'Commands:\n'

# Install the project and dev dependencies into .venv (uv)
sync:
  uv sync

# Run the unit tests
test *args:
  uv run pytest {{args}}

# Run the unit tests with a coverage report
test-cov:
  uv run pytest --cov --cov-report=term-missing

# Lint and check formatting
lint:
  uv run ruff check src tests
  uv run ruff format --check src tests

# Format the code and apply safe lint fixes
format:
  uv run ruff format src tests
  uv run ruff check --fix src tests

# Release checks that must hold between releases too (CI runs the same)
release-check:
  python3 tools/release.py --check
  python3 tools/release_notes.py --check

# The commits since the last tag, as changelog entry candidates (add --write to insert them)
release-draft *args:
  python3 tools/release.py --draft {{args}}

# Cut a release: changelog, version bump, tests, commit, tag, push; CI publishes notes and PyPI
release version *args:
  python3 tools/release.py {{version}} --push {{args}}

# Build the wheel and sdist into dist/
build:
  rm -rf dist
  uv build

# Upload a local build to PyPI (fallback for when the release workflow cannot; needs UV_PUBLISH_TOKEN)
publish: build
  uv publish
