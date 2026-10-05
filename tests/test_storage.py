"""Storages under /FILER and their folders."""

import grp
import os
import pwd

import pytest

from tests.fake_host import G


def test_storage_list_shows_storage01(client, host, filer):
    r = client.get("/storage")
    assert r.status_code == 200
    [s] = r.json()
    assert s["name"] == "STORAGE01"
    assert s["mountpoint"] == str(filer / "STORAGE01")
    assert s["disk"] == "sdb" and s["device"] == "/dev/sdb1"
    assert s["layout"] == "raw" and s["vg"] is None and s["lv"] is None
    assert s["fstype"] == "ext4" and s["uuid"] == "bbbb-storage01"
    assert s["protected"] is True
    assert s["managed"] is False  # mounted by hand (fstab), no unit file
    assert s["exports"] == 6
    assert s["folders"] == 6
    assert s["size"] > 0 and s["size_human"].endswith(("G", "T", "M"))


def test_storage_list_includes_lvm_and_unmounted_is_absent(
    client, host, filer, tmp_path
):
    (filer / "STORAGE02").mkdir()
    host.add_disk("sdc", 500 * G)
    host.add_part("sdc")
    host.add_lv(
        "vg_storage02", "data", "sdc1", uuid="cccc", mountpoint=str(filer / "STORAGE02")
    )
    from zboxapi import storage

    storage.mount_unit_path("STORAGE02").write_text("[Mount]\n")
    host.add_disk("sdd", 2 * 1024**4)
    host.add_part("sdd", fstype="ext4", label="STORAGE03")  # not mounted: not a storage

    names = [
        (s["name"], s["layout"], s["managed"]) for s in client.get("/storage").json()
    ]
    assert names == [("STORAGE01", "raw", False), ("STORAGE02", "lvm", True)]
    s2 = client.get("/storage/STORAGE02").json()
    assert s2["vg"] == "vg_storage02" and s2["lv"] == "data"
    assert s2["device"] == "/dev/mapper/vg_storage02-data"
    assert s2["protected"] is False


def test_mount_unit_names_follow_systemd_escaping(host, filer, tmp_path, monkeypatch):
    from zboxapi import storage

    assert storage.systemd_escape_path("/FILER/STORAGE02") == "FILER-STORAGE02"
    assert storage.systemd_escape_path("/mnt/my-disk") == "mnt-my\\x2ddisk"
    assert storage.mount_unit_path("STORAGE02").name.endswith("-FILER-STORAGE02.mount")
    assert (
        storage.mount_unit_path("STORAGE02").parent
        == tmp_path / "etc" / "systemd" / "system"
    )


def test_storage_get_404(client, host):
    r = client.get("/storage/STORAGE09")
    assert r.status_code == 404


def test_storage_folders(client, host, filer):
    (filer / "STORAGE01" / "scratch").mkdir()
    (filer / "STORAGE01" / "a-file.txt").write_text("not a folder")
    r = client.get("/storage/STORAGE01/folder")
    assert r.status_code == 200
    by = {f["name"]: f for f in r.json()}
    assert set(by) == {
        "NFS-01",
        "NFS-02",
        "NFS-03",
        "NFS-04",
        "NFS-05",
        "NFS-VCD",
        "scratch",
    }
    assert by["NFS-01"]["exported"] is True and by["NFS-01"]["empty"] is False
    assert by["NFS-02"]["exported"] is True and by["NFS-02"]["empty"] is True
    assert by["scratch"]["exported"] is False and by["scratch"]["empty"] is True
    assert by["scratch"]["path"] == str(filer / "STORAGE01" / "scratch")
    assert len(by["scratch"]["mode"]) == 4 and ":" in by["scratch"]["owner"]


# ── folders: create, chown/chmod, delete ─────────────────────────────────────────────

ME = f"{pwd.getpwuid(os.getuid()).pw_name}:{grp.getgrgid(os.getgid()).gr_name}"


def test_folder_create_with_defaults_from_config(client, host, filer, tmp_path):
    # defaults: folder_owner root:root would fail as non-root, so point config at us
    conf = tmp_path / "etc" / "zboxapi.conf"
    conf.write_text(conf.read_text() + f"folder_owner = {ME}\nfolder_mode = 0775\n")
    r = client.post("/storage/STORAGE01/folder", json={"name": "NFS-06"})
    assert r.status_code == 200, r.text
    assert r.json() == {
        "name": "NFS-06",
        "path": str(filer / "STORAGE01" / "NFS-06"),
        "exported": False,
        "empty": True,
        "mode": "0775",
        "owner": ME,
    }
    assert (filer / "STORAGE01" / "NFS-06").is_dir()
    assert "folder-perms" in (tmp_path / "audit.log").read_text()


def test_folder_create_with_explicit_owner_and_mode(client, host, filer):
    r = client.post(
        "/storage/STORAGE01/folder",
        json={"name": "scratch", "owner": ME, "mode": "750"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "0750" and r.json()["owner"] == ME
    assert oct((filer / "STORAGE01" / "scratch").stat().st_mode & 0o7777) == "0o750"


def test_folder_create_accepts_numeric_owner(client, host, filer):
    owner = f"{os.getuid()}:{os.getgid()}"
    r = client.post(
        "/storage/STORAGE01/folder",
        json={"name": "num", "owner": owner, "mode": "0700"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["owner"] == ME  # reported back as names


@pytest.mark.parametrize(
    "payload, message",
    [
        ({"name": "../escape"}, "Invalid folder name"),
        ({"name": "a/b"}, "Invalid folder name"),
        ({"name": ".."}, "Invalid folder name"),
        ({"name": "-leading"}, "Invalid folder name"),
        ({"name": "x" * 64}, "Invalid folder name"),
        ({"name": "ok", "owner": "nobody-such-user-zz:root"}, "Unknown user"),
        ({"name": "ok", "owner": "root:no-such-group-zz"}, "Unknown group"),
        ({"name": "ok", "owner": "root"}, "use user:group"),
        ({"name": "ok", "mode": "0999"}, "Invalid mode"),
        ({"name": "ok", "mode": "rwx"}, "Invalid mode"),
    ],
)
def test_folder_create_rejects_bad_input(client, host, filer, payload, message):
    r = client.post("/storage/STORAGE01/folder", json=payload)
    assert r.status_code == 422
    assert message in r.text
    if payload["name"] != "..":
        assert not (filer / "STORAGE01" / payload["name"]).exists()


def test_folder_create_conflicts_and_404(client, host, filer):
    r = client.post("/storage/STORAGE01/folder", json={"name": "NFS-02", "owner": ME})
    assert r.status_code == 409
    r = client.post("/storage/STORAGE09/folder", json={"name": "x", "owner": ME})
    assert r.status_code == 404


def test_folder_update_chmod_and_chown(client, host, filer, tmp_path):
    target = filer / "STORAGE01" / "NFS-02"
    r = client.put("/storage/STORAGE01/folder/NFS-02", json={"mode": "0755"})
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "0755"
    assert oct(target.stat().st_mode & 0o7777) == "0o755"

    r = client.put(
        "/storage/STORAGE01/folder/NFS-02", json={"owner": ME, "mode": "777"}
    )
    assert r.status_code == 200
    assert r.json()["owner"] == ME and r.json()["mode"] == "0777"

    r = client.put("/storage/STORAGE01/folder/NFS-02", json={})
    assert r.status_code == 422
    assert "owner, a mode, or both" in r.text

    assert (
        client.put("/storage/STORAGE01/folder/nope", json={"mode": "0755"}).status_code
        == 404
    )


def test_folder_update_recursive_reaches_children(client, host, filer):
    base = filer / "STORAGE01" / "NFS-02"
    (base / "vm-a").mkdir()
    (base / "vm-a" / "disk.vmdk").write_text("x")
    (base / "vm-a" / "disk.vmdk").chmod(0o600)
    (base / "vm-a").chmod(0o700)

    r = client.put("/storage/STORAGE01/folder/NFS-02", json={"mode": "0770"})
    assert r.status_code == 200
    assert oct((base / "vm-a").stat().st_mode & 0o7777) == "0o700"  # not recursive

    r = client.put(
        "/storage/STORAGE01/folder/NFS-02", json={"mode": "0770", "recursive": True}
    )
    assert r.status_code == 200
    assert oct((base / "vm-a").stat().st_mode & 0o7777) == "0o770"
    assert oct((base / "vm-a" / "disk.vmdk").stat().st_mode & 0o7777) == "0o770"


def test_folder_delete(client, host, filer, tmp_path):
    managed = tmp_path / "etc" / "exports.d" / "zboxapi.exports"
    (filer / "STORAGE01" / "empty").mkdir()
    (filer / "STORAGE01" / "full").mkdir()
    (filer / "STORAGE01" / "full" / "f").write_text("x")
    (filer / "STORAGE01" / "exported").mkdir()
    managed.write_text(f"{filer}/STORAGE01/exported *(rw)\n")

    r = client.delete("/storage/STORAGE01/folder/full")
    assert r.status_code == 409 and "not empty (1 entry)" in r.json()["detail"]
    r = client.delete("/storage/STORAGE01/folder/exported")
    assert r.status_code == 409 and "exported" in r.json()["detail"]
    r = client.delete("/storage/STORAGE01/folder/missing")
    assert r.status_code == 404
    r = client.delete("/storage/STORAGE01/folder/empty")
    assert r.status_code == 200
    assert not (filer / "STORAGE01" / "empty").exists()
    assert (filer / "STORAGE01" / "full" / "f").exists()


@pytest.mark.parametrize(
    "method, path, body",
    [
        ("POST", "/storage/STORAGE01/folder", {"name": "NFS-01"}),
        ("PUT", "/storage/STORAGE01/folder/NFS-01", {"mode": "0777"}),
        (
            "PUT",
            "/storage/STORAGE01/folder/NFS-01",
            {"owner": "root:root", "recursive": True},
        ),
        ("DELETE", "/storage/STORAGE01/folder/NFS-01", None),
    ],
)
def test_folder_endpoints_refuse_nfs01(client, host, filer, method, path, body):
    before = sorted(str(p) for p in (filer / "STORAGE01" / "NFS-01").rglob("*"))
    mode_before = (filer / "STORAGE01" / "NFS-01").stat().st_mode
    r = client.request(method, path, json=body)
    assert r.status_code == 403, r.text
    assert "protected" in r.json()["detail"]
    assert sorted(str(p) for p in (filer / "STORAGE01" / "NFS-01").rglob("*")) == before
    assert (filer / "STORAGE01" / "NFS-01").stat().st_mode == mode_before
    assert host.mutating_calls == []
