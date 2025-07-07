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


## Documentation

- [DOC_DNS.md](DOC_DNS.md) - Complete guide to DNS management features
- [DOC_VLAN.md](DOC_VLAN.md) - Complete guide to VLAN management features
