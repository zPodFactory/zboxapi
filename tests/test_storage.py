"""Storages under /FILER and their folders."""

import os

import pytest

from tests.conftest import ME
from tests.fake_host import G, T


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
    assert r.json() == {
        "message": f"Folder {filer / 'STORAGE01' / 'empty'} deleted",
        "path": str(filer / "STORAGE01" / "empty"),
        "removed": 1,
        "forced": False,
    }
    assert not (filer / "STORAGE01" / "empty").exists()
    assert (filer / "STORAGE01" / "full" / "f").exists()
    assert (
        "pass force=true"
        in client.delete("/storage/STORAGE01/folder/full").json()["detail"]
    )


def test_folder_delete_force_removes_contents(client, host, filer, tmp_path):
    base = filer / "STORAGE01" / "NFS-02"
    (base / "vm-a").mkdir()
    (base / "vm-a" / "disk.vmdk").write_text("x" * 100)
    (base / "vm-a" / "nested").mkdir()
    (base / "vm-a" / "nested" / "log").write_text("y")
    (base / "iso.img").write_text("z")
    (base / "link-out").symlink_to(
        filer / "STORAGE01" / "NFS-01"
    )  # must not be followed
    nfs01_before = sorted(str(p) for p in (filer / "STORAGE01" / "NFS-01").rglob("*"))
    (tmp_path / "etc" / "exports").write_text("")  # NFS-02 is not exported in this test
    host.reload_exports()

    r = client.delete("/storage/STORAGE01/folder/NFS-02?force=true")
    assert r.status_code == 200, r.text
    assert r.json()["forced"] is True and r.json()["removed"] == 7
    assert "with 6 entries" in r.json()["message"]
    assert not base.exists()
    assert (
        sorted(str(p) for p in (filer / "STORAGE01" / "NFS-01").rglob("*"))
        == nfs01_before
    )
    assert "rm -rf" in (tmp_path / "audit.log").read_text()


def test_folder_delete_force_still_refuses_exported_and_protected(client, host, filer):
    r = client.delete("/storage/STORAGE01/folder/NFS-02?force=true")
    assert r.status_code == 409
    assert "force does not override this" in r.json()["detail"]
    assert (filer / "STORAGE01" / "NFS-02").is_dir()

    r = client.delete("/storage/STORAGE01/folder/NFS-01?force=true")
    assert r.status_code == 403
    assert (filer / "STORAGE01" / "NFS-01" / "vm-esx01" / "esx01.vmdk").exists()


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


# ── create, adopt, grow, delete ──────────────────────────────────────────────────────


def names(steps):
    return [(s["step"], s["status"]) for s in steps]


def test_create_raw_storage(client, host, filer, tmp_path):
    host.add_disk("sdd", 2 * T)
    r = client.post("/storage", json={"disk": "sdd", "lvm": False, "name": "STORAGE03"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["operation"] == "storage_create" and body["dry_run"] is False
    assert names(body["steps"]) == [
        ("partition", "done"),
        ("settle", "done"),
        ("partx", "done"),
        ("mkfs", "done"),
        ("mountpoint", "done"),
        ("mount-unit", "done"),
        ("daemon-reload", "done"),
        ("mount", "done"),
    ]
    assert "command" not in body["steps"][0]  # not verbose
    s = body["storage"]
    assert s["name"] == "STORAGE03" and s["layout"] == "raw"
    assert s["disk"] == "sdd" and s["device"] == "/dev/sdd1"
    assert s["managed"] is True and s["protected"] is False
    assert s["fstype"] == "ext4"

    part = host.disks["sdd"].parts[0]
    assert host.disks["sdd"].pttype == "gpt"
    assert part.parttype.startswith("0fc63daf") and part.label == "STORAGE03"
    assert part.mountpoint == str(filer / "STORAGE03")
    unit = tmp_path / "etc" / "systemd" / "system"
    [unit_file] = [p for p in unit.iterdir() if p.name.endswith("STORAGE03.mount")]
    text = unit_file.read_text()
    assert f"What=UUID={part.uuid}" in text and f"Where={filer / 'STORAGE03'}" in text
    assert "Options=defaults,noatime,nofail" in text
    assert client.get("/disk/sdd").json()["state"] == "in-use"


def test_create_lvm_storage_with_auto_name(client, host, filer):
    host.add_disk("sdc", 500 * G)
    r = client.post("/storage?verbose=true", json={"disk": "sdc", "lvm": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert [s["step"] for s in body["steps"]] == [
        "partition",
        "settle",
        "partx",
        "pv",
        "vg",
        "lv",
        "mkfs",
        "mountpoint",
        "mount-unit",
        "daemon-reload",
        "mount",
    ]
    assert (
        body["steps"][0]["command"]
        == "sfdisk --quiet /dev/sdc <<< 'label: gpt\n,,lvm\n'"
    )
    assert body["steps"][5]["command"] == "lvcreate -y -l 100%FREE -n data vg_storage02"
    assert body["steps"][6]["command"].startswith("mkfs.ext4 -F -L STORAGE02 -U ")
    assert body["steps"][6]["output"].startswith("Creating filesystem")
    s = body["storage"]
    assert s["name"] == "STORAGE02" and s["layout"] == "lvm"
    assert s["vg"] == "vg_storage02" and s["lv"] == "data"
    assert s["device"] == "/dev/mapper/vg_storage02-data"
    assert host.disks["sdc"].parts[0].fstype == "LVM2_member"
    [lv] = host.lvs
    assert lv.label == "STORAGE02" and lv.mountpoint == str(filer / "STORAGE02")


def test_create_dry_run_changes_nothing(client, host, filer):
    host.add_disk("sdc", 500 * G)
    r = client.post(
        "/storage?dry_run=true&verbose=true", json={"disk": "sdc", "lvm": True}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dry_run"] is True and "storage" not in body
    assert all(s["status"] == "planned" for s in body["steps"])
    assert any(s["command"].startswith("vgcreate vg_storage02") for s in body["steps"])
    assert host.disks["sdc"].pttype is None and host.mutating_calls == []
    assert not (filer / "STORAGE02").exists()


def test_create_refusals(client, host, filer, tmp_path):
    host.add_disk("sdc", 500 * G)
    host.add_disk("sdd", 250 * G, fstype="ntfs")
    cases = [
        ({"disk": "sdb"}, 403, "protected"),
        ({"disk": "sda"}, 403, "system disk"),
        ({"disk": "sdz"}, 404, "not found"),
        ({"disk": "sdd"}, 409, "ntfs signature"),
        ({"disk": "sdc", "name": "STORAGE01"}, 409, "already exists"),
        ({"disk": "sdc", "name": "STORAGE1"}, 422, "Invalid storage name"),
        ({"disk": "sdc", "name": "storage02"}, 422, "Invalid storage name"),
        ({"disk": "sdc", "lvm": "maybe"}, 422, "bool"),
    ]
    for payload, code, message in cases:
        r = client.post("/storage", json=payload)
        assert r.status_code == code, (payload, r.text)
        assert message in r.text, (payload, r.text)
    assert host.mutating_calls == []

    (filer / "STORAGE02").mkdir()
    (filer / "STORAGE02" / "leftover").write_text("x")
    r = client.post("/storage", json={"disk": "sdc"})
    assert r.status_code == 409 and "not empty" in r.json()["detail"]


def test_create_lvm_requires_lvm2(client, host):
    host.add_disk("sdc", 500 * G)
    host.lvm_installed = False
    r = client.post("/storage", json={"disk": "sdc", "lvm": True})
    assert r.status_code == 400
    assert "lvm2 is not installed" in r.json()["detail"]
    r = client.post("/storage", json={"disk": "sdc", "lvm": False})
    assert r.status_code == 200, r.text  # raw still works


def test_create_rolls_back_when_mkfs_fails(client, host, filer, tmp_path):
    host.add_disk("sde", 500 * G)
    host.fail.add(("mkfs.ext4",))
    r = client.post(
        "/storage?verbose=true", json={"disk": "sde", "lvm": True, "name": "STORAGE04"}
    )
    assert r.status_code == 500, r.text
    detail = r.json()["detail"]
    assert "mkfs on /dev/vg_storage04/data failed" in detail["message"]
    statuses = dict(names(detail["steps"]))
    assert statuses["mkfs"] == "failed"
    assert statuses["lv"] == "done" and statuses["mount"] == "planned"  # never reached
    assert [s["step"] for s in detail["rollback"]] == [
        "undo lv",
        "undo vg",
        "undo pv",
        "undo partition",
    ]
    assert all(s["status"] == "done" for s in detail["rollback"])
    assert detail["rollback"][-1]["command"] == "wipefs -a /dev/sde"
    # the disk is blank again, nothing else was created
    assert host.disks["sde"].pttype is None and host.disks["sde"].parts == []
    assert host.lvs == []
    assert client.get("/disk/sde").json()["state"] == "blank"
    assert not (filer / "STORAGE04").exists()
    assert not any(
        p.name.endswith("STORAGE04.mount")
        for p in (tmp_path / "etc" / "systemd" / "system").iterdir()
    )


def test_create_rolls_back_when_mount_fails(client, host, filer, tmp_path):
    host.add_disk("sdd", 2 * T)
    host.fail.add(("systemctl", "enable"))
    r = client.post("/storage", json={"disk": "sdd", "name": "STORAGE03"})
    assert r.status_code == 500
    detail = r.json()["detail"]
    assert [s["step"] for s in detail["rollback"]] == [
        "undo mount-unit",
        "undo mountpoint",
        "undo mkfs",
        "undo partition",
    ]
    assert not (filer / "STORAGE03").exists()
    assert host.disks["sdd"].parts == []


def test_adopt_existing_filesystem(client, host, filer, tmp_path):
    host.add_disk("sdd", 2 * T)
    host.add_part("sdd", fstype="ext4", label="old-data", uuid="dddd-old")
    r = client.post("/storage/adopt?verbose=true", json={"device": "sdd1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert [s["step"] for s in body["steps"]] == [
        "mountpoint",
        "mount-unit",
        "daemon-reload",
        "mount",
    ]
    assert not any(s["step"] in ("partition", "mkfs") for s in body["steps"])
    assert body["storage"]["name"] == "STORAGE02" and body["storage"]["managed"] is True
    assert host.disks["sdd"].parts[0].label == "old-data"  # nothing formatted
    assert host.disks["sdd"].parts[0].mountpoint == str(filer / "STORAGE02")


def test_adopt_lvm_by_vg_lv(client, host, filer):
    host.add_disk("sdc", 500 * G)
    host.add_part("sdc")
    host.add_lv("vg_old", "data", "sdc1", uuid="cccc-old")
    r = client.post(
        "/storage/adopt", json={"device": "vg_old/data", "name": "STORAGE05"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["storage"]["device"] == "/dev/mapper/vg_old-data"
    assert r.json()["storage"]["layout"] == "lvm"


def test_adopt_refusals(client, host, filer):
    host.add_disk("sdd", 2 * T)
    host.add_part("sdd", fstype="xfs", uuid="x")
    host.add_disk("sde", 1 * T)
    host.add_part("sde", fstype="ext4", uuid="e", mountpoint="/mnt/elsewhere")
    host.add_disk("sdf", 1 * T)
    host.add_part("sdf")  # no filesystem
    for payload, code, message in [
        ({"device": "sdb1"}, 403, "protected"),
        ({"device": "sda1"}, 403, "system disk"),
        ({"device": "sdz1"}, 404, "not found"),
        ({"device": "sdd"}, 404, "not found"),  # a whole disk is not a filesystem
        ({"device": "sdd1"}, 409, "has xfs filesystem"),
        ({"device": "sde1"}, 409, "is mounted at /mnt/elsewhere"),
        ({"device": "sdf1"}, 409, "has no filesystem"),
    ]:
        r = client.post("/storage/adopt", json=payload)
        assert r.status_code == code, (payload, r.text)
        assert message in r.text, (payload, r.text)
    assert host.mutating_calls == []


def test_grow_lvm_storage(client, host, filer):
    host.add_disk("sdc", 500 * G)
    assert client.post("/storage", json={"disk": "sdc", "lvm": True}).status_code == 200
    host.mutating_calls.clear()
    host.resize("sdc", T)  # enlarged in vSphere
    r = client.post("/storage/STORAGE02/grow?verbose=true")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["changed"] is True
    assert names(body["steps"]) == [
        ("rescan", "done"),
        ("growpart", "done"),
        ("pvresize", "done"),
        ("lvextend", "done"),
        ("resize2fs", "done"),
    ]
    assert body["steps"][1]["command"] == "growpart /dev/sdc 1"
    assert body["steps"][1]["output"].startswith("CHANGED")
    assert body["steps"][3]["command"] == "lvextend -l +100%FREE /dev/vg_storage02/data"
    assert body["steps"][4]["command"] == "resize2fs /dev/mapper/vg_storage02-data"
    assert body["before"]["disk"] == 500 * G and body["after"]["disk"] == T
    assert body["after"]["partition"] == T - 2 * 1024**2
    assert body["after"]["lv"] == T - 6 * 1024**2
    assert host.disks["sdc"].rescans == 1

    # a second grow is a no-op, not an error
    r = client.post("/storage/STORAGE02/grow")
    assert r.status_code == 200
    assert r.json()["changed"] is False
    assert names(r.json()["steps"]) == [
        ("rescan", "done"),
        ("growpart", "nochange"),
        ("pvresize", "done"),
        ("lvextend", "nochange"),
        ("resize2fs", "done"),
    ]


def test_grow_raw_storage(client, host, filer):
    host.add_disk("sdd", 2 * T)
    assert (
        client.post("/storage", json={"disk": "sdd", "name": "STORAGE03"}).status_code
        == 200
    )
    host.resize("sdd", 4 * T)
    r = client.post("/storage/STORAGE03/grow")
    assert r.status_code == 200, r.text
    assert names(r.json()["steps"]) == [
        ("rescan", "done"),
        ("growpart", "done"),
        ("resize2fs", "done"),
    ]
    assert r.json()["after"]["partition"] == 4 * T - 2 * 1024**2
    assert r.json()["changed"] is True


def test_grow_dry_run_and_refusals(client, host, filer):
    host.add_disk("sdd", 2 * T)
    assert (
        client.post("/storage", json={"disk": "sdd", "name": "STORAGE03"}).status_code
        == 200
    )
    host.resize("sdd", 4 * T)
    r = client.post("/storage/STORAGE03/grow?dry_run=true")
    assert r.status_code == 200
    assert all(s["status"] == "planned" for s in r.json()["steps"])
    assert host.disks["sdd"].size == 2 * T and host.disks["sdd"].rescans == 0

    r = client.post("/storage/STORAGE01/grow")
    assert r.status_code == 403 and "protected" in r.json()["detail"]
    assert host.disks["sdb"].rescans == 0
    assert client.post("/storage/STORAGE09/grow").status_code == 404
    assert client.post("/storage/bad/grow").status_code == 422


def test_grow_an_unmanaged_storage_mounted_by_hand(client, host, filer):
    # mounted via fstab by the operator, no unit file: still growable
    (filer / "STORAGE02").mkdir()
    host.add_disk("sdc", 500 * G)
    host.add_part(
        "sdc", fstype="ext4", uuid="cccc", mountpoint=str(filer / "STORAGE02")
    )
    host.resize("sdc", T)
    r = client.post("/storage/STORAGE02/grow")
    assert r.status_code == 200, r.text
    assert r.json()["changed"] is True


def test_delete_storage(client, host, filer, tmp_path):
    host.add_disk("sdd", 2 * T)
    assert (
        client.post("/storage", json={"disk": "sdd", "name": "STORAGE03"}).status_code
        == 200
    )
    r = client.delete("/storage/STORAGE03")
    assert r.status_code == 200, r.text
    body = r.json()
    assert names(body["steps"]) == [
        ("unmount", "done"),
        ("mount-unit", "done"),
        ("daemon-reload", "done"),
        ("mountpoint", "done"),
    ]
    assert body["disk_state"] == "foreign"
    part = host.disks["sdd"].parts[0]
    assert part.mountpoint is None and part.fstype == "ext4"  # filesystem kept
    assert not (filer / "STORAGE03").exists()
    assert not any(
        p.name.endswith("STORAGE03.mount")
        for p in (tmp_path / "etc" / "systemd" / "system").iterdir()
    )
    assert client.get("/storage/STORAGE03").status_code == 404
    # and the disk cannot be re-created without a wipe by hand
    r = client.post("/storage", json={"disk": "sdd"})
    assert r.status_code == 409 and "ext4 signature on sdd1" in r.json()["detail"]


def test_delete_refusals(client, host, filer, tmp_path):
    host.add_disk("sdd", 2 * T)
    assert (
        client.post("/storage", json={"disk": "sdd", "name": "STORAGE03"}).status_code
        == 200
    )
    (tmp_path / "etc" / "exports.d" / "zboxapi.exports").write_text(
        f"{filer}/STORAGE03/NFS-20 *(rw)\n"
    )
    r = client.delete("/storage/STORAGE03")
    assert r.status_code == 409 and "has 1 export" in r.json()["detail"]
    assert "NFS-20" in r.json()["detail"]

    r = client.delete("/storage/STORAGE01")
    assert r.status_code == 403 and "protected" in r.json()["detail"]
    assert host.disks["sdb"].parts[0].mountpoint == str(filer / "STORAGE01")

    (filer / "STORAGE02").mkdir()
    host.add_disk("sdc", 500 * G)
    host.add_part(
        "sdc", fstype="ext4", uuid="cccc", mountpoint=str(filer / "STORAGE02")
    )
    r = client.delete("/storage/STORAGE02")  # mounted by hand, no unit
    assert r.status_code == 409 and "not mounted by this API" in r.json()["detail"]
    assert client.delete("/storage/STORAGE09").status_code == 404


def test_full_lifecycle_add_export_grow_remove(client, host, filer, tmp_path):
    from tests.fake_host import Disk

    host.hotplug(Disk(name="sdc", size=500 * G, serial="6000c29sdc"))
    assert client.post("/disk/rescan").json()["new"] == ["sdc"]
    assert client.post("/storage", json={"disk": "sdc", "lvm": True}).status_code == 200
    r = client.post(
        "/storage/STORAGE02/folder",
        json={"name": "NFS-15", "owner": ME, "mode": "0777"},
    )
    assert r.status_code == 200, r.text
    host.resize("sdc", T)
    assert client.post("/disk/rescan").json()["resized"][0]["storage"] == "STORAGE02"
    assert client.post("/storage/STORAGE02/grow").json()["changed"] is True
    listing = {s["name"]: s for s in client.get("/storage").json()}
    assert (
        listing["STORAGE02"]["folders"] == 1 and listing["STORAGE02"]["layout"] == "lvm"
    )
    assert client.delete("/storage/STORAGE02/folder/NFS-15").status_code == 200
    assert client.delete("/storage/STORAGE02").json()["disk_state"] == "foreign"
    assert [s["name"] for s in client.get("/storage").json()] == ["STORAGE01"]
    # the protected disk never saw a single command
    assert host.snapshot("sdb") == host.snapshot("sdb")
    assert not any("sdb" in " ".join(c) for c in host.mutating_calls)
