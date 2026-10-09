import configparser
import contextlib
import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, status
from pydantic import AfterValidator, BaseModel, Field
from pydantic_core import PydanticCustomError

from zboxapi import config, guard, system

# Paths managed by this API (module-level so tests can override)
CONFIG_FILE = Path("/etc/zboxapi.conf")
INTERFACES_DIR = Path("/etc/network/interfaces.d")


class ConfigError(Exception):
    """Configuration error"""

    pass


class NetworkError(Exception):
    """Network configuration error"""

    pass


def load_config() -> configparser.ConfigParser:
    """Load configuration from /etc/zboxapi.conf"""
    config = configparser.ConfigParser()
    config_path = CONFIG_FILE

    if not config_path.exists():
        raise ConfigError(f"Configuration file {config_path} not found")

    config.read(config_path)
    return config


def get_config_value(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    default: str | None = None,
) -> str:
    """Get configuration value with optional default"""
    try:
        return config.get(section, key)
    except configparser.NoSectionError, configparser.NoOptionError:
        if default is not None:
            return default
        raise ConfigError(f"Configuration missing: [{section}] {key}") from None


def get_system_vlans_default() -> list[int]:
    """Get system default VLANs from configuration"""
    config = load_config()
    system_vlans_str = get_config_value(
        config, "DEFAULT", "system_vlans_default", "10,20,30"
    )
    try:
        return [int(v.strip()) for v in system_vlans_str.split(",")]
    except ValueError as e:
        raise ConfigError("Invalid system_vlans_default configuration") from e


def get_system_vlans_zpod() -> list[int]:
    """Get system zPod VLANs from configuration"""
    config = load_config()
    system_vlans_str = get_config_value(
        config, "DEFAULT", "system_vlans_zpod", "64,128,192"
    )
    try:
        return [int(v.strip()) for v in system_vlans_str.split(",")]
    except ValueError as e:
        raise ConfigError("Invalid system_vlans_zpod configuration") from e


def get_interface_name() -> str:
    """Get interface name from configuration"""
    config = load_config()
    return get_config_value(config, "DEFAULT", "interface", "eth1")


def get_mtu() -> int:
    """Get MTU from configuration"""
    config = load_config()
    try:
        return int(get_config_value(config, "DEFAULT", "mtu", "1700"))
    except ValueError as e:
        raise ConfigError("Invalid MTU configuration") from e


def validate_vlan_id(vlan_id: int) -> int:
    """Validate VLAN ID is in valid range and not a system VLAN"""
    if not 1 <= vlan_id <= 4094:
        raise PydanticCustomError("value_error", "VLAN ID must be between 1 and 4094")

    system_vlans_default = get_system_vlans_default()
    system_vlans_zpod = get_system_vlans_zpod()

    if vlan_id in system_vlans_default:
        raise PydanticCustomError(
            "value_error",
            f"VLAN {vlan_id} is a system default VLAN and cannot be modified",
        )

    if vlan_id in system_vlans_zpod:
        raise PydanticCustomError(
            "value_error",
            f"VLAN {vlan_id} is a system zPod VLAN and cannot be modified",
        )

    return vlan_id


def validate_cidr(cidr: str) -> str:
    """Validate CIDR notation, but preserve the original input."""
    try:
        # Parse the CIDR to validate it's correct
        ipaddress.IPv4Network(cidr, strict=False)
        # But return the original input, not the normalized network
        return cidr
    except ValueError as e:
        raise PydanticCustomError("value_error", f"Invalid CIDR: {e}") from e


def check_no_overlap(cidrs):
    """
    Check a list of CIDR networks for overlaps.
    Raises ValueError if any two networks overlap.

    Args:
        cidrs (list[str]): List of CIDR notation strings (e.g., "192.168.0.0/24").

    Returns:
        bool: True if no overlaps are found.

    Raises:
        ValueError: If any two networks overlap.
    """
    # Parse strings into IPv4Network/IPv6Network objects with strict=False
    # This allows host addresses like 172.16.10.1/24 to be converted to 172.16.10.0/24
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]

    # Compare each pair for overlap
    for i, net1 in enumerate(networks):
        for net2 in networks[i + 1 :]:
            if net1.overlaps(net2):
                raise ValueError(f"Networks {net1} and {net2} overlap")

    # No overlaps detected
    return True


def host_networks() -> list[tuple[str, str]]:
    """Every IPv4 address configured on the host as (interface, cidr), from
    `ip -o -4 addr show`; the loopback left out."""
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True
        )
    except OSError:
        return []
    if result.returncode != 0:
        return []
    out = []
    for line in result.stdout.splitlines():
        # "3: eth1    inet 10.60.60.1/26 brd 10.60.60.63 scope global eth1\ ..."
        m = re.match(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if m and m.group(1) != "lo":
            out.append((m.group(1), m.group(2)))
    return out


def validate_vlan_networks(
    new_gateway: str, exclude_vlan_id: int | None = None
) -> None:
    """The new gateway's network may not overlap with any network already present on
    the host: the configured VLANs (user-defined files and system VLANs) and every
    IPv4 address on any interface, the base interface and eth0 included."""
    interface_name = get_interface_name()
    excluded = f"{interface_name}.{exclude_vlan_id}" if exclude_vlan_id else None
    new_net = ipaddress.ip_network(new_gateway, strict=False)

    taken: list[tuple[str, str]] = []  # (what, cidr)
    for vlan in get_existing_vlans():
        if exclude_vlan_id is not None and vlan.vlan == exclude_vlan_id:
            continue
        # System VLANs whose interface has no address carry a placeholder
        # ("system-default" / "system-zpod") instead of a CIDR: nothing to compare.
        try:
            ipaddress.ip_network(vlan.gateway, strict=False)
        except ValueError:
            continue
        taken.append((f"VLAN {vlan.vlan} on {vlan.interface}", vlan.gateway))
    known_ifaces = {what.split(" on ", 1)[1] for what, _ in taken}
    for iface, cidr in host_networks():
        if iface == excluded or iface in known_ifaces:
            continue
        taken.append((f"interface {iface}", cidr))

    for what, cidr in taken:
        other = ipaddress.ip_network(cidr, strict=False)
        if new_net.overlaps(other):
            raise NetworkError(
                f"Network {new_net} (gateway {new_gateway}) overlaps with {what} "
                f"({cidr}, network {other})"
            )


VLAN_ID = Annotated[int, AfterValidator(validate_vlan_id)]
CIDR = Annotated[str, AfterValidator(validate_cidr)]


class VlanCreate(BaseModel):
    vlan: VLAN_ID = Field(..., description="VLAN ID (1-4094, excluding system VLANs)")
    gateway: CIDR = Field(..., description="Gateway IP address in CIDR notation")
    masquerade: bool = Field(
        False,
        description="source-translate traffic from this VLAN that leaves on the "
        "management interface (SNAT to its address); off by default",
    )


class VlanMasquerade(BaseModel):
    enabled: bool


class VlanUpdate(BaseModel):
    gateway: CIDR = Field(..., description="Gateway IP address in CIDR notation")


class VlanView(BaseModel):
    vlan: int
    gateway: str
    interface: str
    status: Literal["up", "down"]
    owner: Literal["user-defined", "system-default", "system-zpod"]
    masquerade: bool = False  # always False for system VLANs


@contextlib.contextmanager
def get_vlan_config_file_object(vlan_id: int):
    """Context manager for safely handling VLAN config files in interfaces.d/"""
    interface_name = get_interface_name()
    config_dir = INTERFACES_DIR
    config_file = config_dir / f"{interface_name}.{vlan_id}.cfg"

    # Ensure the directory exists
    config_dir.mkdir(mode=0o755, exist_ok=True)

    while True:
        try:
            file_handle = config_file.open("w")  # Use write mode for individual files
            fcntl.flock(file_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError:
            time.sleep(0.1)

    try:
        yield file_handle
    finally:
        fcntl.flock(file_handle, fcntl.LOCK_UN)
        file_handle.close()


def get_interface_status(interface_name_full: str) -> str:
    """Return up if the interface exists and is up, otherwise down"""
    try:
        result = subprocess.run(
            ["ip", "link", "show", interface_name_full],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and "UP" in result.stdout:
            return "up"
    except Exception:
        pass
    return "down"


def get_interface_gateway(interface_name_full: str) -> str | None:
    """Return the first inet address (CIDR) of an interface, if any"""
    try:
        result = subprocess.run(
            ["ip", "addr", "show", interface_name_full],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", result.stdout)
            if ip_match:
                return ip_match.group(1)
    except Exception:
        pass
    return None


def get_system_vlan_view(interface_name: str, vlan_id: int, owner: str) -> VlanView:
    """Build the view of a system VLAN from the live interface state"""
    interface_name_full = f"{interface_name}.{vlan_id}"
    return VlanView(
        vlan=vlan_id,
        gateway=get_interface_gateway(interface_name_full) or owner,
        interface=interface_name_full,
        status=get_interface_status(interface_name_full),
        owner=owner,
    )


def get_user_vlan_view(
    interface_name: str,
    vlan_id: int,
    config_file: Path,
    masqueraded: set[int] | None = None,
) -> VlanView | None:
    """Build the view of a user-defined VLAN from its interfaces.d config file"""
    try:
        content = config_file.read_text()
    except OSError:
        return None

    # Extract gateway from the configuration
    gateway_match = re.search(r"address\s+(\d+\.\d+\.\d+\.\d+/\d+)", content)
    if not gateway_match:
        return None

    interface_name_full = f"{interface_name}.{vlan_id}"
    return VlanView(
        vlan=vlan_id,
        gateway=gateway_match.group(1),
        interface=interface_name_full,
        status=get_interface_status(interface_name_full),
        owner="user-defined",
        masquerade=vlan_id in (masqueraded or set()),
    )


def get_existing_vlans() -> list[VlanView]:
    """Get all VLANs: system VLANs from config plus user VLANs from interfaces.d/"""
    interface_name = get_interface_name()
    config_dir = INTERFACES_DIR
    masqueraded = masqueraded_vlans()  # one nft read per request, not one per VLAN

    system_vlans_default = get_system_vlans_default()
    system_vlans_zpod = get_system_vlans_zpod()

    vlans = [
        get_system_vlan_view(interface_name, vlan_id, "system-default")
        for vlan_id in system_vlans_default
    ]
    vlans.extend(
        get_system_vlan_view(interface_name, vlan_id, "system-zpod")
        for vlan_id in system_vlans_zpod
    )

    # Add user-configured VLANs from interfaces.d/
    if config_dir.exists():
        vlan_pattern = rf"{re.escape(interface_name)}\.(\d+)\.cfg$"

        for config_file in config_dir.glob(f"{interface_name}.*.cfg"):
            match = re.match(vlan_pattern, config_file.name)
            if not match:
                continue

            vlan_id = int(match.group(1))

            # Skip if this is a system VLAN (already added above)
            if vlan_id in system_vlans_default or vlan_id in system_vlans_zpod:
                continue

            if view := get_user_vlan_view(
                interface_name, vlan_id, config_file, masqueraded
            ):
                vlans.append(view)

    return sorted(vlans, key=lambda x: x.vlan)


def add_vlan_interface(vlan_id: int, gateway: str) -> None:
    """Add VLAN interface configuration to /etc/network/interfaces.d/"""
    interface_name = get_interface_name()
    mtu = get_mtu()

    # Validate inputs - check for overlaps and gateway uniqueness
    validate_vlan_networks(gateway)

    # Check if VLAN configuration file already exists
    config_file = INTERFACES_DIR / f"{interface_name}.{vlan_id}.cfg"

    if config_file.exists():
        raise NetworkError(f"VLAN interface {interface_name}.{vlan_id} already exists")

    # Create VLAN configuration
    vlan_config = f"""auto {interface_name}.{vlan_id}
iface {interface_name}.{vlan_id} inet static
    address {gateway}
    mtu {mtu}
"""

    # Write to dedicated configuration file
    with get_vlan_config_file_object(vlan_id) as f:
        f.write(vlan_config)


def update_vlan_interface(vlan_id: int, gateway: str) -> None:
    """Update VLAN interface configuration in /etc/network/interfaces.d/"""
    interface_name = get_interface_name()
    mtu = get_mtu()

    # Validate inputs - check for overlaps, excluding the VLAN being updated
    validate_vlan_networks(gateway, exclude_vlan_id=vlan_id)

    # Check if VLAN configuration file exists
    config_file = INTERFACES_DIR / f"{interface_name}.{vlan_id}.cfg"

    if not config_file.exists():
        raise NetworkError(f"VLAN interface {interface_name}.{vlan_id} does not exist")

    # Create updated VLAN configuration
    vlan_config = f"""auto {interface_name}.{vlan_id}
iface {interface_name}.{vlan_id} inet static
    address {gateway}
    mtu {mtu}
"""

    # Write updated configuration to file
    with get_vlan_config_file_object(vlan_id) as f:
        f.write(vlan_config)


def delete_vlan_interface(vlan_id: int) -> None:
    """Delete VLAN interface configuration from /etc/network/interfaces.d/"""
    interface_name = get_interface_name()
    config_file = INTERFACES_DIR / f"{interface_name}.{vlan_id}.cfg"

    if not config_file.exists():
        raise NetworkError(f"VLAN interface {interface_name}.{vlan_id} does not exist")

    interface_name_full = f"{interface_name}.{vlan_id}"

    # Step 1: Bring interface down
    try:
        bring_interface_down(interface_name_full)
        print(f"Interface {interface_name_full} brought down")
    except Exception as e:
        print(f"Warning: Could not bring down interface {interface_name_full}: {e}")
        # Continue with deletion even if interface is already down

    # Step 2: Delete the configuration file
    try:
        config_file.unlink()
        print(f"Configuration file {config_file} deleted")
    except Exception as e:
        raise NetworkError(f"Failed to delete VLAN configuration file: {e}") from e


def bring_interface_up(interface_name: str) -> None:
    """Bring up a network interface"""
    try:
        subprocess.run(
            ["ifup", interface_name], check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as e:
        raise NetworkError(
            f"Failed to bring up interface {interface_name}: {e.stderr}"
        ) from e


def bring_interface_down(interface_name: str) -> None:
    """Bring down a network interface"""
    try:
        subprocess.run(
            ["ifdown", interface_name], check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as e:
        raise NetworkError(
            f"Failed to bring down interface {interface_name}: {e.stderr}"
        ) from e


# ── masquerade: one nftables rule per VLAN, in one file zboxapi owns ────────────────

MASQ_HEADER = (
    "# Managed by zboxapi (/vlan masquerade). Do not edit; "
    "the file is rewritten on every change.\n"
)
MASQ_COMMENT_RE = re.compile(r"^zboxapi vlan (\d+)$")


def masquerade_available() -> bool:
    return shutil.which("nft") is not None


def nft_file() -> Path:
    return Path(config.get("masquerade", "nft_file"))


def nft_table() -> str:
    return config.get("masquerade", "table")


def out_interface() -> str:
    return config.get("masquerade", "out_interface")


def masqueraded_vlans() -> set[int]:
    """The VLAN ids with a rule in the live table. The live ruleset is the truth; the
    file is only how it survives a reboot. No nft, or no table yet: an empty set."""
    if not masquerade_available():
        return set()
    result = system.query(
        ["nft", "-j", "list", "table", "inet", nft_table()], check=False
    )
    if result.returncode != 0:  # "No such file or directory": no table yet
        return set()
    try:
        items = json.loads(result.stdout or "{}").get("nftables", [])
    except ValueError:
        return set()
    found = set()
    for item in items:
        rule = item.get("rule") if isinstance(item, dict) else None
        if rule and (m := MASQ_COMMENT_RE.match(str(rule.get("comment", "")))):
            found.add(int(m.group(1)))
    return found


def user_vlan_gateways() -> dict[int, str]:
    """VLAN id -> gateway for every user-defined VLAN (from its interfaces.d file)."""
    return {
        v.vlan: v.gateway for v in get_existing_vlans() if v.owner == "user-defined"
    }


def render_masquerade(vlans: set[int], gateways: dict[int, str]) -> str:
    """The whole file for this set of VLANs. `add` + `flush` make loading it
    idempotent and leave every other table alone; zero VLANs is the empty skeleton."""
    table, oif = nft_table(), out_interface()
    rules = []
    for vlan_id in sorted(vlans):
        if vlan_id not in gateways:
            continue  # its interface file is gone: the rule goes with it
        net = ipaddress.ip_network(gateways[vlan_id], strict=False)
        rules.append(
            f'        ip saddr {net} oifname "{oif}" masquerade '
            f'comment "zboxapi vlan {vlan_id}"\n'
        )
    return (
        MASQ_HEADER
        + f"add table inet {table}\n"
        + f"flush table inet {table}\n"
        + f"table inet {table} {{\n"
        + "    chain postrouting {\n"
        + "        type nat hook postrouting priority srcnat; policy accept;\n"
        + "".join(rules)
        + "    }\n"
        + "}\n"
    )


def write_nft_file(text: str) -> None:
    path = nft_file()
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


def apply_masquerade_set(vlans: set[int], source: str = "vlan_masquerade") -> None:
    """Render the file for `vlans`, write it, load it with nft -f. On a failed load
    the previous file content is written back, so file and kernel never disagree."""
    if not masquerade_available():
        raise NetworkError("nftables is not installed on this host (nft not found)")
    path = nft_file()
    previous = path.read_text() if path.is_file() else None
    write_nft_file(render_masquerade(vlans, user_vlan_gateways()))
    result = system.run(["nft", "-f", str(path)], check=False, source=source)
    if result.returncode != 0:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            write_nft_file(previous)
        raise NetworkError(
            f"nft -f {path} failed ({result.returncode}): "
            f"{(result.stderr or result.stdout or '').strip()}"
        )


def set_masquerade(
    vlan_id: int, enabled: bool, source: str = "vlan_masquerade"
) -> bool:
    """Make the VLAN masqueraded or not. Returns whether anything changed; when the
    VLAN is already in the requested state nothing is written and nothing runs."""
    with system.storage_lock():
        current = masqueraded_vlans()
        wanted = current | {vlan_id} if enabled else current - {vlan_id}
        if wanted == current:
            return False
        if not enabled and not masquerade_available():
            return False  # nothing can be masqueraded without nft
        apply_masquerade_set(wanted, source)
        return True


def refresh_masquerade(vlan_id: int, source: str = "vlan_masquerade") -> bool:
    """After a gateway change: re-render the rules if this VLAN has one."""
    with system.storage_lock():
        current = masqueraded_vlans()
        if vlan_id not in current:
            return False
        apply_masquerade_set(current, source)
        return True


# API Router
vlan_router = APIRouter(prefix="/vlan", tags=["vlan"])


@vlan_router.get("", response_model=list[VlanView])
def vlan_get_all() -> list[VlanView]:
    """Get all VLAN interfaces"""
    try:
        return get_existing_vlans()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get VLAN interfaces: {str(e)}",
        ) from e


@vlan_router.get("/{vlan_id}", response_model=VlanView)
def vlan_get(vlan_id: int) -> VlanView:
    """Get specific VLAN interface"""
    try:
        vlans = get_existing_vlans()
        for vlan in vlans:
            if vlan.vlan == vlan_id:
                return vlan

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"VLAN {vlan_id} not found"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get VLAN {vlan_id}: {str(e)}",
        ) from e


@vlan_router.post("", response_model=VlanView)
def vlan_create(vlan_in: VlanCreate) -> VlanView:
    """Create a new VLAN interface"""
    try:
        # Validate VLAN ID
        validate_vlan_id(vlan_in.vlan)

        # Add VLAN interface configuration
        add_vlan_interface(vlan_in.vlan, vlan_in.gateway)

        # Bring up the interface
        interface_name = get_interface_name()
        vlan_interface = f"{interface_name}.{vlan_in.vlan}"
        bring_interface_up(vlan_interface)
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create VLAN: {str(e)}",
        ) from e

    # The interface exists; masquerading is a second, separately reported step
    if vlan_in.masquerade:
        try:
            set_masquerade(vlan_in.vlan, True)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"VLAN {vlan_in.vlan} created, but masquerading could not be "
                f"enabled: {e}. Retry with PUT /vlan/{vlan_in.vlan}/masquerade",
            ) from e

    # Return the created VLAN, masquerade read back from the live table
    return VlanView(
        vlan=vlan_in.vlan,
        gateway=vlan_in.gateway,
        interface=vlan_interface,
        status="up",
        owner="user-defined",
        masquerade=vlan_in.vlan in masqueraded_vlans(),
    )


@vlan_router.put("/{vlan_id}", response_model=VlanView)
def vlan_update(vlan_id: int, vlan_in: VlanUpdate) -> VlanView:
    """Update a VLAN interface"""
    try:
        # Validate VLAN ID
        validate_vlan_id(vlan_id)

        # Update VLAN interface configuration
        update_vlan_interface(vlan_id, vlan_in.gateway)

        # Restart the interface
        interface_name = get_interface_name()
        vlan_interface = f"{interface_name}.{vlan_id}"
        bring_interface_down(vlan_interface)
        bring_interface_up(vlan_interface)
    except PydanticCustomError as e:
        # System VLANs are forbidden from modification
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update VLAN {vlan_id}: {str(e)}",
        ) from e

    # If the VLAN is masqueraded, its rule follows the new subnet
    try:
        refresh_masquerade(vlan_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"VLAN {vlan_id} updated to {vlan_in.gateway}, but its masquerade "
            f"rule still names the old subnet: {e}. Repair with "
            f'PUT /vlan/{vlan_id}/masquerade {{"enabled": true}}',
        ) from e

    return VlanView(
        vlan=vlan_id,
        gateway=vlan_in.gateway,
        interface=vlan_interface,
        status="up",
        owner="user-defined",
        masquerade=vlan_id in masqueraded_vlans(),
    )


@vlan_router.delete("/{vlan_id}")
def vlan_delete(vlan_id: int) -> dict:
    """Delete a VLAN interface"""
    try:
        # Validate VLAN ID
        validate_vlan_id(vlan_id)

        # Its masquerade rule goes first, so no packet is translated for a subnet
        # that is about to vanish; a failure here does not block the delete
        note = ""
        try:
            set_masquerade(vlan_id, False)
        except Exception as e:  # noqa: BLE001 - reported, not fatal
            note = f" (masquerade rule could not be removed: {e})"

        # Delete VLAN configuration (brings the interface down first)
        delete_vlan_interface(vlan_id)

        return {"message": f"VLAN {vlan_id} deleted successfully{note}"}
    except PydanticCustomError as e:
        # System VLANs are forbidden from modification
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete VLAN {vlan_id}: {str(e)}",
        ) from e


@vlan_router.put("/{vlan_id}/masquerade", response_model=VlanView)
def vlan_masquerade(vlan_id: int, body: VlanMasquerade) -> VlanView:
    """Masquerade a VLAN's traffic leaving on the management interface, or stop.
    200 whether or not anything changed."""
    try:
        validate_vlan_id(vlan_id)
    except PydanticCustomError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"VLAN {vlan_id} is a system VLAN and cannot be masqueraded",
        ) from e
    interface_name = get_interface_name()
    if not (INTERFACES_DIR / f"{interface_name}.{vlan_id}.cfg").is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VLAN {vlan_id} does not exist",
        )
    if body.enabled and not masquerade_available():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="nftables is not installed on this host (nft not found)",
        )
    try:
        set_masquerade(vlan_id, body.enabled)
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
        ) from e
    for vlan in get_existing_vlans():
        if vlan.vlan == vlan_id:
            return vlan
    raise HTTPException(status.HTTP_404_NOT_FOUND, f"VLAN {vlan_id} not found")


@vlan_router.put("/{vlan_id}/enable")
def vlan_enable(vlan_id: int) -> dict:
    """Enable a VLAN interface (bring it up)"""
    try:
        # Validate VLAN ID
        validate_vlan_id(vlan_id)

        interface_name = get_interface_name()
        vlan_interface = f"{interface_name}.{vlan_id}"

        # Check if interface exists
        result = subprocess.run(
            ["ip", "link", "show", vlan_interface],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"VLAN interface {vlan_interface} does not exist",
            )

        # Bring interface up
        result = subprocess.run(
            ["ip", "link", "set", vlan_interface, "up"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise NetworkError(
                f"Failed to enable interface {vlan_interface}: {result.stderr}"
            )

        return {"message": f"VLAN {vlan_id} enabled successfully"}
    except PydanticCustomError as e:
        # System VLANs are forbidden from modification
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except HTTPException:
        raise
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enable VLAN {vlan_id}: {str(e)}",
        ) from e


@vlan_router.put("/{vlan_id}/disable")
def vlan_disable(vlan_id: int) -> dict:
    """Disable a VLAN interface (bring it down)"""
    try:
        # Validate VLAN ID
        validate_vlan_id(vlan_id)

        interface_name = get_interface_name()
        vlan_interface = f"{interface_name}.{vlan_id}"

        # Check if interface exists
        result = subprocess.run(
            ["ip", "link", "show", vlan_interface],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"VLAN interface {vlan_interface} does not exist",
            )

        # Bring interface down
        result = subprocess.run(
            ["ip", "link", "set", vlan_interface, "down"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise NetworkError(
                f"Failed to disable interface {vlan_interface}: {result.stderr}"
            )

        return {"message": f"VLAN {vlan_id} disabled successfully"}
    except PydanticCustomError as e:
        # System VLANs are forbidden from modification
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
    except HTTPException:
        raise
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to disable VLAN {vlan_id}: {str(e)}",
        ) from e
