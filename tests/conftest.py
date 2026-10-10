"""Shared fixtures: temp hosts/config paths, a fake command runner, and an
authenticated TestClient. No test touches /etc or runs real system commands."""

import grp
import json
import os
import pwd
import re
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import zboxapi.config as config
import zboxapi.dns as dns
import zboxapi.main as main
import zboxapi.nfs as nfs
import zboxapi.storage as storage
import zboxapi.system as system_mod
import zboxapi.vlan as vlan
from tests.fake_host import FakeHost, zcore

PASSWORD = "s3cret-zpod-password"
ME = f"{pwd.getpwuid(os.getuid()).pw_name}:{grp.getgrgid(os.getgid()).gr_name}"
EXPORT_OPTS = "rw,no_subtree_check,no_root_squash"

CONFIG_TEXT = """[DEFAULT]
interface = eth1
mtu = 1700
system_vlans_default = 10,20,30
system_vlans_zpod = 64,128,192
"""


class FakeSystem:
    """Stand-in for subprocess.run / subprocess.call.

    Simulates the handful of commands zboxapi shells out to (ip, ifup, ifdown,
    pkill) against an in-memory table of interfaces, and records every call.
    """

    def __init__(self):
        self.calls: list[list[str]] = []
        self.mutating_calls: list[list[str]] = []  # commands that changed the model
        self.links: dict[str, str] = {}  # interface -> "up" | "down"
        self.addresses: dict[str, str] = {}  # interface -> CIDR
        self.fail: set[tuple[str, ...]] = set()  # command prefixes that fail
        # nftables model: the live rules of table inet zboxapi, vlan id -> network;
        # None means the table does not exist yet (fresh host)
        self.nft_rules: dict[int, str] | None = None
        self.nft_foreign: list[str] = []  # rule comments not ours, in our table
        self.nft_installed = True

    # -- helpers used by tests -------------------------------------------
    def add_link(self, name: str, state: str = "up", address: str | None = None):
        self.links[name] = state
        if address:
            self.addresses[name] = address

    def calls_starting_with(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if tuple(c[: len(prefix)]) == prefix]

    # -- subprocess API ---------------------------------------------------
    def run(self, cmd, **kwargs) -> subprocess.CompletedProcess:
        cmd = list(cmd)
        self.calls.append(cmd)
        rc, out, err = self._dispatch(cmd)
        if kwargs.get("check") and rc != 0:
            raise subprocess.CalledProcessError(rc, cmd, output=out, stderr=err)
        return subprocess.CompletedProcess(cmd, rc, out, err)

    def call(self, cmd, **kwargs) -> int:
        cmd = list(cmd)
        self.calls.append(cmd)
        return self._dispatch(cmd)[0]

    def _dispatch(self, cmd: list[str]) -> tuple[int, str, str]:  # noqa: C901
        for prefix in self.fail:
            if tuple(cmd[: len(prefix)]) == prefix:
                return 1, "", f"fake failure: {' '.join(cmd)}"

        match cmd:
            case ["ip", "link", "show", iface]:
                if iface not in self.links:
                    return 1, "", f'Device "{iface}" does not exist.'
                state = self.links[iface]
                flags = (
                    "BROADCAST,MULTICAST,UP,LOWER_UP"
                    if state == "up"
                    else ("BROADCAST,MULTICAST")
                )
                return 0, f"5: {iface}@eth1: <{flags}> mtu 1700 state {state}\n", ""
            case ["ip", "addr", "show", iface]:
                if iface not in self.links:
                    return 1, "", f'Device "{iface}" does not exist.'
                out = f"5: {iface}@eth1: <BROADCAST,MULTICAST> mtu 1700\n"
                if iface in self.addresses:
                    out += f"    inet {self.addresses[iface]} scope global {iface}\n"
                return 0, out, ""
            case ["nft", "-j", "list", "table", "inet", table]:
                if self.nft_rules is None:
                    return (
                        1,
                        "",
                        f"Error: No such file or directory\nlist table inet {table}",
                    )
                items = [{"metainfo": {"version": "1.1.3", "json_schema_version": 1}}]
                items.append({"table": {"family": "inet", "name": table, "handle": 1}})
                items.append(
                    {
                        "chain": {
                            "family": "inet",
                            "table": table,
                            "name": "postrouting",
                            "handle": 1,
                            "type": "nat",
                            "hook": "postrouting",
                            "prio": 100,
                            "policy": "accept",
                        }
                    }
                )
                for vlan_id, net in sorted(self.nft_rules.items()):
                    items.append(
                        {
                            "rule": {
                                "family": "inet",
                                "table": table,
                                "chain": "postrouting",
                                "handle": 10 + vlan_id,
                                "comment": f"zboxapi vlan {vlan_id}",
                                "expr": [
                                    {
                                        "match": {
                                            "op": "==",
                                            "left": {
                                                "payload": {
                                                    "protocol": "ip",
                                                    "field": "saddr",
                                                }
                                            },
                                            "right": {
                                                "prefix": {
                                                    "addr": net.split("/")[0],
                                                    "len": int(net.split("/")[1]),
                                                }
                                            },
                                        }
                                    },
                                    {"masquerade": None},
                                ],
                            }
                        }
                    )
                for comment in self.nft_foreign:
                    items.append(
                        {
                            "rule": {
                                "family": "inet",
                                "table": table,
                                "chain": "postrouting",
                                "handle": 999,
                                "comment": comment,
                                "expr": [{"masquerade": None}],
                            }
                        }
                    )
                return 0, json.dumps({"nftables": items}), ""
            case ["nft", "list", "table", "inet", table]:
                if self.nft_rules is None:
                    return 1, "", "Error: No such file or directory"
                return 0, f"table inet {table} {{\n}}\n", ""
            case ["nft", "delete", "table", "inet", table]:
                self.mutating_calls.append(cmd)
                if self.nft_rules is None:
                    return 1, "", "Error: No such file or directory"
                self.nft_rules = None
                self.nft_foreign = []
                return 0, "", ""
            case ["nft", "-f", path]:
                text = Path(path).read_text()
                rules = {}
                for m in re.finditer(
                    r'ip saddr (\S+) oifname "(\S+)" masquerade '
                    r'comment "zboxapi vlan (\d+)"',
                    text,
                ):
                    rules[int(m.group(3))] = m.group(1)
                if "flush table inet" in text:
                    self.nft_foreign = []  # flush empties our table, foreign rules too
                self.nft_rules = rules
                return 0, "", ""
            case ["ip", "-o", "-4", "addr", "show"]:
                lines = [
                    f"{i}: {name}    inet {cidr} brd 0.0.0.0 scope global {name}"
                    "\\       valid_lft forever preferred_lft forever"
                    for i, (name, cidr) in enumerate(self.addresses.items(), 2)
                ]
                return 0, "".join(ln + "\n" for ln in lines), ""
            case ["ip", "link", "set", iface, state]:
                if iface not in self.links:
                    return 1, "", f'Cannot find device "{iface}"'
                self.links[iface] = state
                return 0, "", ""
            case ["ifup", iface]:
                self.links[iface] = "up"
                return 0, "", ""
            case ["ifdown", iface]:
                self.links[iface] = "down"
                return 0, "", ""
            case ["pkill", "-SIGHUP", "dnsmasq"]:
                return 0, "", ""
        return 127, "", f"unknown command: {cmd}"


@pytest.fixture
def system(monkeypatch) -> FakeSystem:
    """Route every subprocess.run / subprocess.call through FakeSystem."""
    fake = FakeSystem()
    monkeypatch.setattr(subprocess, "run", fake.run)
    monkeypatch.setattr(subprocess, "call", fake.call)
    return fake


@pytest.fixture
def hosts_file(tmp_path, monkeypatch):
    """A throwaway hosts file seeded with localhost, wired into zboxapi.dns."""
    path = tmp_path / "hosts"
    path.write_text("127.0.0.1\tlocalhost\n")
    monkeypatch.setattr(dns, "HOSTS_FILE", path)
    return path


@pytest.fixture
def vlan_config(tmp_path, monkeypatch):
    """A throwaway zboxapi.conf, wired into zboxapi.vlan."""
    path = tmp_path / "zboxapi.conf"
    path.write_text(CONFIG_TEXT)
    monkeypatch.setattr(vlan, "CONFIG_FILE", path)
    return path


@pytest.fixture
def interfaces_dir(tmp_path, monkeypatch):
    """A throwaway interfaces.d directory, wired into zboxapi.vlan."""
    path = tmp_path / "interfaces.d"
    path.mkdir()
    monkeypatch.setattr(vlan, "INTERFACES_DIR", path)
    return path


@pytest.fixture
def filer(tmp_path, monkeypatch):
    """A temp /FILER with STORAGE01 and its folders, plus the storage/nfs config."""
    root = tmp_path / "FILER"
    for name in ("NFS-01", "NFS-02", "NFS-03", "NFS-04", "NFS-05", "NFS-VCD"):
        (root / "STORAGE01" / name).mkdir(parents=True)
    (root / "STORAGE01" / "NFS-01" / "vm-esx01").mkdir()
    (root / "STORAGE01" / "NFS-01" / "vm-esx01" / "esx01.vmdk").write_text("data")

    etc = tmp_path / "etc"
    (etc / "exports.d").mkdir(parents=True)
    (etc / "systemd" / "system").mkdir(parents=True)
    s1 = f"{root}/STORAGE01"
    (etc / "exports").write_text(
        f"{s1}/NFS-01 10.60.60.0/26({EXPORT_OPTS})\n"
        f"{s1}/NFS-02 10.60.60.0/26({EXPORT_OPTS})\n"
        f"{s1}/NFS-03 192.168.0.0/26({EXPORT_OPTS}) *({EXPORT_OPTS})\n"
        f"{s1}/NFS-04 10.60.60.0/26({EXPORT_OPTS})\n"
        f"{s1}/NFS-05 192.168.0.0/24({EXPORT_OPTS})\n"
        f"{s1}/NFS-VCD 10.60.60.0/26({EXPORT_OPTS})\n"
    )
    (etc / "zboxapi.conf").write_text(
        "[storage]\n"
        f"filer_root = {root}\n"
        f"mount_unit_dir = {etc / 'systemd' / 'system'}\n"
        "[nfs]\n"
        f"exports_file = {etc / 'exports.d' / 'zboxapi.exports'}\n"
        f"system_exports_file = {etc / 'exports'}\n"
        f"protected_exports = {root}/STORAGE01/NFS-01\n"
        f"folder_owner = {ME}\n"  # the API runs as root on zcore; the tests do not
        "[masquerade]\n"
        f"nft_file = {etc / 'nftables.d' / 'zboxapi-masquerade.nft'}\n"
    )
    monkeypatch.setattr(config, "CONFIG_FILE", etc / "zboxapi.conf")
    monkeypatch.setattr(system_mod, "AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(system_mod, "LOCK_FILE", tmp_path / "storage.lock")
    monkeypatch.setattr(system_mod, "SYS_BLOCK", tmp_path / "sys" / "block")
    monkeypatch.setattr(system_mod, "SYS_SCSI_HOST", tmp_path / "sys" / "scsi_host")
    nfsd = tmp_path / "proc" / "fs" / "nfsd"
    nfsd.mkdir(parents=True)
    (nfsd / "versions").write_text("-2 +3 +4 +4.1 +4.2\n")
    (nfsd / "threads").write_text("8\n")
    (nfsd / "clients").mkdir()
    monkeypatch.setattr(nfs, "PROC_NFSD", nfsd)
    monkeypatch.setattr(nfs, "RMTAB", tmp_path / "rmtab")
    return root


@pytest.fixture
def host(filer, system, monkeypatch, tmp_path) -> FakeHost:
    """zcore as it is today, with subprocess.run routed through the model."""
    fake = zcore(tmp_path)
    fake.fallback = system
    etc = tmp_path / "etc"
    fake.exports_files = [etc / "exports", etc / "exports.d" / "zboxapi.exports"]
    fake.reload_exports()
    fake.attach_sysfs(tmp_path / "sys")
    fake.unit_dir = etc / "systemd" / "system"
    monkeypatch.setattr(subprocess, "run", fake.run)
    monkeypatch.setattr(storage, "lvm_available", lambda: fake.lvm_installed)
    monkeypatch.setattr(vlan, "masquerade_available", lambda: system.nft_installed)
    return fake


@pytest.fixture
def password(monkeypatch) -> str:
    """Replace the vmtoolsd lookup with a fixed password."""
    monkeypatch.setattr(main, "get_zpod_password", lambda: PASSWORD)
    return PASSWORD


@pytest.fixture
def anon_client(password, hosts_file, vlan_config, interfaces_dir, system, host):
    """TestClient with the app fully sandboxed but no credentials attached."""
    with TestClient(main.app) as client:
        yield client


@pytest.fixture
def client(anon_client, password):
    """Authenticated TestClient."""
    anon_client.headers["access_token"] = password
    return anon_client


def write_user_vlan(interfaces_dir, vlan_id: int, gateway: str, interface="eth1"):
    """Drop a user VLAN config file the way add_vlan_interface would."""
    (interfaces_dir / f"{interface}.{vlan_id}.cfg").write_text(
        f"auto {interface}.{vlan_id}\n"
        f"iface {interface}.{vlan_id} inet static\n"
        f"    address {gateway}\n"
        f"    mtu 1700\n"
    )
