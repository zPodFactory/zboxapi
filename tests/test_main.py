"""Application wiring: authentication, password lookup, startup, OpenAPI."""

import subprocess

import pytest
from fastapi.testclient import TestClient

import zboxapi
import zboxapi.main as main
from tests.conftest import PASSWORD

OVFENV = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<Environment>\n<PropertySection>\n'
    '<Property oe:key="guestinfo.hostname" oe:value="zbox"/>\n'
    '<Property oe:key="guestinfo.password" oe:value="Sup3r!Secret"/>\n'
    "</PropertySection>\n</Environment>\n"
)


def test_requests_without_token_are_rejected(anon_client):
    r = anon_client.get("/dns")
    assert r.status_code == 403
    assert r.json() == {"detail": "Invalid access_token"}


def test_requests_with_wrong_token_are_rejected(anon_client):
    r = anon_client.get("/dns", headers={"access_token": "nope"})
    assert r.status_code == 403


@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/dns"),
        ("POST", "/dns"),
        ("GET", "/dns/127.0.0.1/localhost"),
        ("PUT", "/dns/127.0.0.1/localhost"),
        ("DELETE", "/dns/127.0.0.1/localhost"),
        ("GET", "/vlan"),
        ("POST", "/vlan"),
        ("GET", "/vlan/2000"),
        ("PUT", "/vlan/2000"),
        ("DELETE", "/vlan/2000"),
        ("PUT", "/vlan/2000/enable"),
        ("PUT", "/vlan/2000/disable"),
        ("GET", "/disk"),
        ("GET", "/disk/sda"),
        ("POST", "/disk/rescan"),
        ("POST", "/storage"),
        ("POST", "/storage/adopt"),
        ("POST", "/storage/STORAGE01/grow"),
        ("DELETE", "/storage/STORAGE01"),
        ("GET", "/storage"),
        ("GET", "/storage/STORAGE01"),
        ("POST", "/storage/STORAGE01/NFS-02"),
        ("PUT", "/storage/STORAGE01/NFS-02"),
        ("DELETE", "/storage/STORAGE01/NFS-02"),
        ("GET", "/nfs"),
        ("GET", "/nfs/STORAGE01/NFS-01"),
    ],
)
def test_every_endpoint_requires_auth(anon_client, method, path):
    assert anon_client.request(method, path).status_code == 403


def test_requests_with_correct_token_succeed(client):
    assert client.get("/dns").status_code == 200
    assert client.get("/vlan").status_code == 200


def test_get_zpod_password_parses_ovfenv(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, OVFENV, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert main.get_zpod_password.__wrapped__() == "Sup3r!Secret"
    assert calls == [["vmtoolsd", "--cmd", "info-get guestinfo.ovfenv"]]


def test_get_zpod_password_without_property_raises(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "<Environment/>", ""),
    )
    with pytest.raises(Exception, match="Unable to retrieve zpod password"):
        main.get_zpod_password.__wrapped__()


def test_startup_fails_fast_when_password_unavailable(monkeypatch):
    def boom():
        raise RuntimeError("no vmtoolsd here")

    monkeypatch.setattr(main, "get_zpod_password", boom)
    with pytest.raises(RuntimeError, match="no vmtoolsd here"):
        with TestClient(main.app):
            pass


def test_openapi_metadata_and_operation_ids(client):
    spec = client.get("/openapi.json").json()
    assert spec["info"]["title"] == "zBox API"
    assert spec["info"]["version"] == zboxapi.__version__
    ops = {
        op["operationId"]
        for methods in spec["paths"].values()
        for op in methods.values()
    }
    assert ops == {
        "dns_dns_get_all",
        "dns_dns_get",
        "dns_dns_add",
        "dns_dns_update",
        "dns_dns_delete",
        "vlan_vlan_get_all",
        "vlan_vlan_get",
        "vlan_vlan_create",
        "vlan_vlan_update",
        "vlan_vlan_delete",
        "vlan_vlan_enable",
        "vlan_vlan_disable",
        "disk_disk_get_all",
        "disk_disk_get",
        "disk_disk_rescan",
        "storage_storage_create",
        "storage_storage_adopt",
        "storage_storage_grow",
        "storage_storage_delete",
        "storage_storage_get_all",
        "storage_storage_get",
        "storage_storage_folder_create",
        "storage_storage_folder_update",
        "storage_storage_folder_delete",
        "nfs_nfs_get_all",
        "nfs_nfs_get",
    }


def test_version_matches_installed_package():
    from importlib.metadata import version

    assert zboxapi.__version__ == version("zboxapi")
    assert PASSWORD  # sanity: fixtures module importable
