# VLAN Management API

The zboxapi now includes a comprehensive VLAN management system that allows you to create, read, update, and delete VLAN interfaces with proper validation and network configuration management.

This system is designed to provide a simple way to create VLAN interfaces on the zbox eth1.x interface. (such as a VyOS router)


## Configuration

The VLAN management system uses a configuration file located at `/etc/zboxapi.conf`. Create this file with the following structure:

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

### Configuration Options

- **interface**: The base network interface name (e.g., `eth1`, `ens3`)
- **mtu**: Maximum Transmission Unit for VLAN interfaces
- **system_vlans_default**: Comma-separated list of default system VLAN IDs that cannot be modified
- **system_vlans_zpod**: Comma-separated list of zPod system VLAN IDs that cannot be modified

## API Endpoints

### 1. Create VLAN Interface
**POST** `/vlan`

Creates a new VLAN interface with the specified VLAN ID and gateway.

**Request Body:**
```json
{
    "vlan": 2000,
    "gateway": "192.168.42.129/25"
}
```

**Response:**
```json
{
    "vlan": 2000,
    "gateway": "192.168.42.129/25",
    "interface": "eth1.2000",
    "status": "up"
}
```

### 2. List All VLAN Interfaces
**GET** `/vlan`

Returns all configured VLAN interfaces.

**Response:**
```json
[
    {
        "vlan": 2000,
        "gateway": "192.168.42.129/25",
        "interface": "eth1.2000",
        "status": "up"
    },
    {
        "vlan": 3000,
        "gateway": "10.10.10.1/24",
        "interface": "eth1.3000",
        "status": "down"
    }
]
```

### 3. Get Specific VLAN Interface
**GET** `/vlan/{vlan_id}`

Returns information about a specific VLAN interface.

**Response:**
```json
{
    "vlan": 2000,
    "gateway": "192.168.42.129/25",
    "interface": "eth1.2000",
    "status": "up"
}
```

### 4. Update VLAN Interface
**PUT** `/vlan/{vlan_id}`

Updates the gateway configuration for a specific VLAN interface.

**Request Body:**
```json
{
    "gateway": "192.168.66.1/24"
}
```

**Response:**
```json
{
    "vlan": 2000,
    "gateway": "192.168.66.1/24",
    "interface": "eth1.2000",
    "status": "up"
}
```

### 5. Delete VLAN Interface
**DELETE** `/vlan/{vlan_id}`

Deletes a VLAN interface configuration and removes the interface from the system.

**Process:**
1. Brings the interface down gracefully using `ifdown`
2. Removes the configuration file from `/etc/network/interfaces.d/`

**Response:**
```json
{
    "message": "VLAN 2000 deleted successfully"
}
```

**Logs during deletion:**
```
Interface eth1.2000 brought down
Configuration file /etc/network/interfaces.d/eth1.2000.cfg deleted
```

## Validation Rules

### VLAN ID Validation
- Must be between 1 and 4094
- Cannot be in the `system_vlans_default` list (10,20,30)
- Cannot be in the `system_vlans_zpod` list (0,64,128,192)
- Must be unique (no duplicate VLAN IDs)

### Gateway CIDR Validation
- Must be valid IPv4 CIDR notation (e.g., `192.168.1.1/24`)
- **Preserves the exact IP address provided** (no network address normalization)
- **No network overlaps allowed between any VLANs**
- Uses the `ipaddress` Python module for validation

### Network Overlap Detection
The system uses a comprehensive `check_no_overlap()` function that validates all VLAN networks simultaneously:

```python
def check_no_overlap(cidrs):
    """Check a list of CIDR networks for overlaps."""
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]

    for i, net1 in enumerate(networks):
        for net2 in networks[i+1:]:
            if net1.overlaps(net2):
                raise ValueError(f"Networks {net1} and {net2} overlap")

    return True
```

This approach ensures:
1. **No duplicate gateways** (same network = overlap)
2. **No overlapping subnets** (e.g., 192.168.1.0/24 and 192.168.1.128/25)
3. **No partial overlaps** (any network intersection is rejected)
4. **Host address support** (e.g., 172.16.10.1/24 is automatically converted to 172.16.10.0/24 for overlap checking)

**Examples of Rejected Configurations:**
```json
// This will be rejected - same gateway as existing VLAN
{
    "vlan": 42,
    "gateway": "192.168.42.1/26"
}
{
    "vlan": 43,
    "gateway": "192.168.42.1/26"  // ❌ Same network = overlap
}

// This will be rejected - overlapping networks
{
    "vlan": 42,
    "gateway": "192.168.42.1/26"
}
{
    "vlan": 43,
    "gateway": "192.168.42.64/26"  // ❌ Overlaps with VLAN 42
}

// This will be accepted - non-overlapping networks
{
    "vlan": 42,
    "gateway": "192.168.42.1/26"
}
{
    "vlan": 43,
    "gateway": "192.168.43.1/26"  // ✅ No overlap
}
```

## File Structure

VLAN configurations are stored in individual files under `/etc/network/interfaces.d/`:

```
/etc/network/interfaces.d/
├── eth1.2000.cfg
├── eth1.3000.cfg
└── eth1.4000.cfg
```

Each configuration file contains:
```
auto eth1.2000
iface eth1.2000 inet static
    address 192.168.42.129/25
    mtu 1700
```

## Error Handling

The API provides comprehensive error handling with proper HTTP status codes:

- **400 Bad Request**: Validation errors (invalid VLAN ID, network overlaps, etc.)
- **403 Forbidden**: Attempting to modify system VLANs (default: 10,20,30 or zPod: 0,64,128,192)
- **404 Not Found**: VLAN interface does not exist
- **500 Internal Server Error**: System configuration or network errors

All exceptions are properly chained using `raise ... from e` for better debugging.