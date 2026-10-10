"""Tolerant reader for /etc/zboxapi.conf sections that have defaults for every key.

The VLAN router keeps its own stricter loader (a missing file is an error there). The
storage and nfs routers work without a file: every key below has a default.
"""

import configparser
from pathlib import Path

# Module-level so tests can point it at a temporary file
CONFIG_FILE = Path("/etc/zboxapi.conf")

DEFAULTS: dict[str, dict[str, str]] = {
    "storage": {
        "filer_root": "/FILER",
        "protected_storages": "STORAGE01",
        "mount_unit_dir": "/etc/systemd/system",
        "filesystem": "ext4",
        "mkfs_options": "-m 0",
        "mount_options": "defaults,noatime,nofail",
    },
    "masquerade": {
        "out_interface": "eth0",
        "nft_file": "/etc/nftables.d/zboxapi-masquerade.nft",
        "table": "zboxapi",
    },
    "nfs": {
        "exports_file": "/etc/exports.d/zboxapi.exports",
        "system_exports_file": "/etc/exports",
        "protected_exports": "/FILER/STORAGE01/NFS-01",
        "export_options": "rw,no_subtree_check,no_root_squash",
        "folder_mode": "0777",
        "folder_owner": "root:root",
    },
}


def read_config() -> configparser.ConfigParser:
    """The config file, or an empty parser when there is none."""
    config = configparser.ConfigParser()
    if CONFIG_FILE.is_file():
        config.read(CONFIG_FILE)
    return config


def get(section: str, key: str) -> str:
    """A value from the file, or its default. Unknown keys are a programming error."""
    default = DEFAULTS[section][key]
    config = read_config()
    try:
        return config.get(section, key)
    except configparser.NoSectionError, configparser.NoOptionError:
        return default


def get_list(section: str, key: str) -> list[str]:
    """A comma-separated value as a list, blanks dropped."""
    return [v.strip() for v in get(section, key).split(",") if v.strip()]
