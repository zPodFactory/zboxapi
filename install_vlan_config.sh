#!/bin/bash

# VLAN Management Configuration Installer
# This script sets up the configuration file for VLAN management

set -e

CONFIG_FILE="/etc/zboxapi.conf"
EXAMPLE_CONFIG="etc/zboxapi.conf.example"

echo "zBoxApi VLAN Management Configuration Installer"
echo "================================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Check if configuration file already exists
if [[ -f "$CONFIG_FILE" ]]; then
    echo "Configuration file $CONFIG_FILE already exists."
    read -p "Do you want to backup and overwrite it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        echo "Backup created: ${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    else
        echo "Installation cancelled."
        exit 0
    fi
fi

# Check if example config exists
if [[ ! -f "$EXAMPLE_CONFIG" ]]; then
    echo "Error: Example configuration file $EXAMPLE_CONFIG not found."
    echo "Please run this script from the zboxapi directory."
    exit 1
fi

# Copy example configuration
echo "Installing configuration file..."
cp "$EXAMPLE_CONFIG" "$CONFIG_FILE"

# Set proper permissions
chmod 644 "$CONFIG_FILE"
chown root:root "$CONFIG_FILE"

echo "Configuration file installed: $CONFIG_FILE"
echo ""
echo "Please review and edit the configuration file:"
echo "  sudo nano $CONFIG_FILE"
echo ""
echo "Configuration options:"
echo "  - interface: Base network interface name (e.g., eth1, ens3)"
echo "  - mtu: Maximum Transmission Unit for VLAN interfaces"
echo "  - system_vlans: Comma-separated list of reserved VLAN IDs"
echo ""
echo "After configuration, restart the zboxapi service:"
echo "  sudo systemctl restart zboxapi.service"
echo ""
echo "For detailed documentation, see DOC_VLAN.md"