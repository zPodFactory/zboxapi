set dotenv-load
set positional-arguments

@_default:
  just --list --list-heading $'Commands:\n'

# Create a release version
zboxapi-release version:
  #!/usr/bin/env bash
  set -euo pipefail

  # Verify gh is installed
  if ! command -v gh >/dev/null 2>&1; then
      echo 'Install gh first'
      exit 1
  fi

  # Verify user is logged into gh
  if ! gh auth status >/dev/null 2>&1; then
      echo 'You need to login: gh auth login'
      exit 1
  fi

  # Verify that repo is clean
  cd {{justfile_directory()}}
  if [[ `git status --porcelain` ]]; then
    # Dirty repo
    echo 'Uncommited changes in repo.  Commit or remove changes before creating release.'
    exit 1
  fi

  # Set version
  poetry version {{version}}
  newversion=$(poetry version -s)

  # Commit changes
  git commit -am"Version v${newversion}"
  git push

  # Create github release
  gh release create v${newversion} --generate-notes

  # Build and publish zboxapi
  cd {{justfile_directory()}}
  poetry build
  poetry publish
