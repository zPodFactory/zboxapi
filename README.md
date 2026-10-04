# zBoxApi

zPodFactory zBox Api

## Features

- **DNS Management**: Manage DNS records in `/etc/hosts` with automatic dnsmasq integration
- **VLAN Management**: Manage VLAN interfaces with automatic network configuration

## Installation

Complete the following steps to set up zBox Api:

1. Install pipx

    ```bash
    # Install and configure pipx
    apt update
    apt install -y pipx
    pipx ensurepath

    # Reload your profile
    source ~/.zshrc
    ```

1. Install zBoxApi:

    ```bash
    pipx install zboxapi
    ```

    Or with [uv](https://docs.astral.sh/uv/), which also fetches a suitable Python if needed:

    ```bash
    uv tool install zboxapi
    ```

    zBoxApi supports Python 3.10 through 3.14.

1. Set up and start zboxapi.service

    ```bash
    cp zboxapi.service /etc/systemd/system
    systemctl daemon-reload
    systemctl enable zboxapi.service
    systemctl start zboxapi.service
    ```

    **Note**: The service runs on `127.0.0.1:8000` and requires root privileges for network configuration operations.

## Configuration

### VLAN Management

For VLAN management functionality, create a configuration file at `/etc/zboxapi.conf`:

```ini
[DEFAULT]
# Base interface name for VLAN management
interface = eth1

# MTU setting for VLAN interfaces
mtu = 1700

# System default VLANs that cannot be modified (comma-separated)
system_vlans_default = 10,20,30

# System zPod VLANs that cannot be modified (comma-separated)
system_vlans_zpod = 64,128,192
```

See [DOC_VLAN.md](DOC_VLAN.md) for detailed documentation on VLAN management features.

## API Usage

### Authentication

All API endpoints require authentication using the `access_token` header. The API key is the zPod password which is also the root password of the zbox VM. The password is automatically retrieved from VMware tools:

```bash
curl -H "access_token: your_zpod_password" http://127.0.0.1:8000/dns
```

**Note**: The service runs on `127.0.0.1:8000` and requires root privileges for network configuration operations.

### DNS Management

Manage DNS records in `/etc/hosts`:

```bash
# Add DNS record
curl -X POST "http://127.0.0.1:8000/dns" \
     -H "access_token: your_zpod_password" \
     -H "Content-Type: application/json" \
     -d '{"ip": "192.168.1.100", "hostname": "example.com"}'

# List all DNS records
curl -X GET "http://127.0.0.1:8000/dns" \
     -H "access_token: your_zpod_password"
```

For complete DNS management documentation, see [DOC_DNS.md](DOC_DNS.md).

### VLAN Management

Manage VLAN interfaces:

```bash
# Create VLAN interface
curl -X POST "http://127.0.0.1:8000/vlan" \
     -H "access_token: your_zpod_password" \
     -H "Content-Type: application/json" \
     -d '{"vlan": 2000, "gateway": "192.168.42.129/25"}'

# List all VLAN interfaces
curl -X GET "http://127.0.0.1:8000/vlan" \
     -H "access_token: your_zpod_password"
```

For complete VLAN management documentation, see [DOC_VLAN.md](DOC_VLAN.md).


## Development

The project is managed with [uv](https://docs.astral.sh/uv/). Clone the repository, then:

```bash
uv sync                 # create .venv with the project and dev dependencies
uv run pytest           # run the unit tests (no root, /etc or network access needed)
uv run pytest --cov     # same, with a coverage report
uv run ruff check src tests && uv run ruff format --check src tests
```

A `justfile` wraps the same commands (`just test`, `just lint`, `just format`).

### Releasing

Every change gets a line under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md). A release is
one command:

```bash
python3 tools/release.py 0.2.0 --push      # or: just release 0.2.0
```

It turns `[Unreleased]` into a dated `[0.2.0]` section, bumps `pyproject.toml` and `uv.lock`,
runs the tests, commits, tags `v0.2.0` and pushes. The tag then runs
`.github/workflows/release.yml`, which publishes the changelog section as the GitHub release
note, builds the package with `uv build`, publishes it to PyPI with `uv publish` and attaches
the wheel and sdist to the release. See [tools/README.md](tools/README.md) for the details,
including the one-time PyPI setup (an API token secret or trusted publishing).

The test suite exercises every endpoint through FastAPI's `TestClient`. The hosts file,
`/etc/zboxapi.conf`, `/etc/network/interfaces.d/` and the `vmtoolsd` password lookup are
redirected to temporary locations, and the `ip`, `ifup`, `ifdown` and `pkill` commands are
replaced by an in-memory fake, so the tests can run on any machine.

## Documentation

- [DOC_DNS.md](DOC_DNS.md) - Complete guide to DNS management features
- [DOC_VLAN.md](DOC_VLAN.md) - Complete guide to VLAN management features
