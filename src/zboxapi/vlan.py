import configparser
import contextlib
import fcntl
import ipaddress
import re
import subprocess
import time
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, status
from pydantic import AfterValidator, BaseModel, Field
from pydantic_core import PydanticCustomError


class ConfigError(Exception):
    """Configuration error"""

    pass


class NetworkError(Exception):
    """Network configuration error"""

    pass


def load_config() -> configparser.ConfigParser:
    """Load configuration from /etc/zboxapi.conf"""
    config = configparser.ConfigParser()
    config_path = Path("/etc/zboxapi.conf")

    if not config_path.exists():
        raise ConfigError("Configuration file /etc/zboxapi.conf not found")

    config.read(config_path)
    return config


def get_config_value(
    config: configparser.ConfigParser, section: str, key: str, default: str = None
) -> str:
    """Get configuration value with optional default"""
    try:
        return config.get(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError):
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
        network = ipaddress.IPv4Network(cidr, strict=False)
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


def validate_vlan_networks(new_gateway: str, exclude_vlan_id: int = None) -> None:
    """Validate that a new gateway doesn't overlap with existing VLAN networks"""
    # Get all existing VLAN gateways
    existing_vlans = get_existing_vlans()
    all_gateways = [new_gateway]  # Include the new gateway

    for vlan in existing_vlans:
        # Skip the VLAN we're updating (if this is an update operation)
        if exclude_vlan_id is not None and vlan.vlan == exclude_vlan_id:
            continue
        all_gateways.append(vlan.gateway)

    # Check for overlaps
    try:
        check_no_overlap(all_gateways)
    except ValueError as e:
        raise NetworkError(f"Network overlap detected: {e}") from e


VLAN_ID = Annotated[int, AfterValidator(validate_vlan_id)]
CIDR = Annotated[str, AfterValidator(validate_cidr)]


class VlanCreate(BaseModel):
    vlan: VLAN_ID = Field(..., description="VLAN ID (1-4094, excluding system VLANs)")
    gateway: CIDR = Field(..., description="Gateway IP address in CIDR notation")


class VlanUpdate(BaseModel):
    gateway: CIDR = Field(..., description="Gateway IP address in CIDR notation")


class VlanView(BaseModel):
    vlan: int
    gateway: str
    interface: str
    status: str
    owner: str


@contextlib.contextmanager
def get_vlan_config_file_object(vlan_id: int):
    """Context manager for safely handling VLAN configuration files in /etc/network/interfaces.d/"""
    interface_name = get_interface_name()
    config_dir = Path("/etc/network/interfaces.d")
    config_file = config_dir / f"{interface_name}.{vlan_id}.cfg"

    # Ensure the directory exists
    config_dir.mkdir(mode=0o755, exist_ok=True)

    while True:
        try:
            file_handle = config_file.open("w")  # Use write mode for individual files
            fcntl.flock(file_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except IOError:
            time.sleep(0.1)

    try:
        yield file_handle
    finally:
        fcntl.flock(file_handle, fcntl.LOCK_UN)
        file_handle.close()


def get_existing_vlans() -> list[VlanView]:
    """Get all existing VLAN configurations from /etc/network/interfaces.d/ and system VLANs"""
    interface_name = get_interface_name()
    config_dir = Path("/etc/network/interfaces.d")

    vlans = []

    # Add system default VLANs
    system_vlans_default = get_system_vlans_default()
    for vlan_id in system_vlans_default:
        # Try to get actual gateway from ip addr command
        gateway = "system-default"
        interface_name_full = f"{interface_name}.{vlan_id}"

        # Check if interface is currently up
        status = "down"
        try:
            result = subprocess.run(
                ["ip", "link", "show", interface_name_full],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0 and "UP" in result.stdout:
                status = "up"
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["ip", "addr", "show", interface_name_full],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                # Extract IP address from ip addr output
                ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", result.stdout)
                if ip_match:
                    gateway = ip_match.group(1)
        except Exception:
            pass

        vlans.append(
            VlanView(
                vlan=vlan_id,
                gateway=gateway,
                interface=interface_name_full,
                status=status,
                owner="system-default",
            )
        )

    # Add system zPod VLANs
    system_vlans_zpod = get_system_vlans_zpod()
    for vlan_id in system_vlans_zpod:
        # Try to get actual gateway from ip addr command
        gateway = "system-zpod"
        interface_name_full = f"{interface_name}.{vlan_id}"

        # Check if interface is currently up
        status = "down"
        try:
            result = subprocess.run(
                ["ip", "link", "show", interface_name_full],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0 and "UP" in result.stdout:
                status = "up"
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["ip", "addr", "show", interface_name_full],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                # Extract IP address from ip addr output
                ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", result.stdout)
                if ip_match:
                    gateway = ip_match.group(1)
        except Exception:
            pass

        vlans.append(
            VlanView(
                vlan=vlan_id,
                gateway=gateway,
                interface=interface_name_full,
                status=status,
                owner="system-zpod",
            )
        )

    # Add user-configured VLANs from /etc/network/interfaces.d/
    if config_dir.exists():
        # Find all VLAN configuration files
        vlan_pattern = rf"{re.escape(interface_name)}\.(\d+)\.cfg$"

        for config_file in config_dir.glob(f"{interface_name}.*.cfg"):
            match = re.match(vlan_pattern, config_file.name)
            if not match:
                continue

            vlan_id = int(match.group(1))

            # Skip if this is a system VLAN (already added above)
            if vlan_id in system_vlans_default or vlan_id in system_vlans_zpod:
                continue

            try:
                with open(config_file, "r") as f:
                    content = f.read()

                # Extract gateway from the configuration
                gateway_match = re.search(
                    r"address\s+(\d+\.\d+\.\d+\.\d+/\d+)", content
                )
                if not gateway_match:
                    continue

                gateway = gateway_match.group(1)

                # Check if interface is currently up
                status = "down"
                try:
                    result = subprocess.run(
                        ["ip", "link", "show", f"{interface_name}.{vlan_id}"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if result.returncode == 0 and "UP" in result.stdout:
                        status = "up"
                except Exception:
                    pass

                vlans.append(
                    VlanView(
                        vlan=vlan_id,
                        gateway=gateway,
                        interface=f"{interface_name}.{vlan_id}",
                        status=status,
                        owner="user-defined",
                    )
                )
            except Exception:
                continue  # Skip files that can't be read or parsed

    return sorted(vlans, key=lambda x: x.vlan)


def add_vlan_interface(vlan_id: int, gateway: str) -> None:
    """Add VLAN interface configuration to /etc/network/interfaces.d/"""
    interface_name = get_interface_name()
    mtu = get_mtu()

    # Validate inputs - check for overlaps and gateway uniqueness
    validate_vlan_networks(gateway)

    # Check if VLAN configuration file already exists
    config_dir = Path("/etc/network/interfaces.d")
    config_file = config_dir / f"{interface_name}.{vlan_id}.cfg"

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

    # Validate inputs - check for overlaps and gateway uniqueness, excluding current VLAN
    validate_vlan_networks(gateway, exclude_vlan_id=vlan_id)

    # Check if VLAN configuration file exists
    config_dir = Path("/etc/network/interfaces.d")
    config_file = config_dir / f"{interface_name}.{vlan_id}.cfg"

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
    config_dir = Path("/etc/network/interfaces.d")
    config_file = config_dir / f"{interface_name}.{vlan_id}.cfg"

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

        # Return the created VLAN
        return VlanView(
            vlan=vlan_in.vlan,
            gateway=vlan_in.gateway,
            interface=vlan_interface,
            status="up",
            owner="user-defined",
        )
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create VLAN: {str(e)}",
        ) from e


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

        # Return the updated VLAN
        return VlanView(
            vlan=vlan_id,
            gateway=vlan_in.gateway,
            interface=vlan_interface,
            status="up",
            owner="user-defined",
        )
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update VLAN {vlan_id}: {str(e)}",
        ) from e


@vlan_router.delete("/{vlan_id}")
def vlan_delete(vlan_id: int) -> dict:
    """Delete a VLAN interface"""
    try:
        # Validate VLAN ID
        validate_vlan_id(vlan_id)

        # Delete VLAN interface configuration (includes bringing down and deleting interface)
        delete_vlan_interface(vlan_id)

        return {"message": f"VLAN {vlan_id} deleted successfully"}
    except (ConfigError, NetworkError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        ) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete VLAN {vlan_id}: {str(e)}",
        ) from e


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
