"""Block device inventory and classification."""

from tests.fake_host import Disk, G, T
from zboxapi.disk import classify


def test_inventory_classifies_every_disk(client, host):
    host.add_disk("sdc", 500 * G)  # nothing on it
    host.add_disk("sdd", 250 * G, fstype="ntfs")  # a signature straight on the disk
    sde = host.add_disk("sde", 2 * T)
    host.add_part("sde", fstype="ext4", label="old")  # partitioned, not mounted
    sdf = host.add_disk("sdf", 500 * G)
    host.add_part("sdf", fstype="LVM2_member")
    host.add_lv(
        "vg_storage02",
        "data",
        "sdf1",
        mountpoint=f"{host.disks['sdb'].parts[0].mountpoint[:-2]}02",
    )
    assert sde and sdf

    r = client.get("/disk")
    assert r.status_code == 200
    by = {d["name"]: d for d in r.json()}
    assert by["sda"]["state"] == "system"
    assert by["sda"]["reason"] == "sda is the system disk (/)"
    assert by["sdb"]["state"] == "protected"
    assert by["sdb"]["storage"] == "STORAGE01"
    assert "holds" in by["sdb"]["reason"]
    assert by["sdc"]["state"] == "blank"
    assert by["sdd"]["state"] == "foreign" and "ntfs signature" in by["sdd"]["reason"]
    assert (
        by["sde"]["state"] == "foreign" and "gpt partition table" in by["sde"]["reason"]
    )
    assert by["sf" if False else "sdf"]["state"] == "in-use"
    assert by["sdf"]["storage"] == "STORAGE02"
    assert by["sdb"]["partitions"][0] == {
        "name": "sdb1",
        "path": "/dev/sdb1",
        "size": T - 2 * 1024**2,
        "size_human": "1024.0G",
        "fstype": "ext4",
        "label": "STORAGE01",
        "uuid": "bbbb-storage01",
        "mountpoint": host.disks["sdb"].parts[0].mountpoint,
    }
    assert by["sdc"]["size_human"] == "500.0G"
    assert by["sdc"]["serial"] == "6000c29sdc"


def test_disk_get_one_and_404(client, host):
    assert client.get("/disk/sda").json()["state"] == "system"
    r = client.get("/disk/sdz")
    assert r.status_code == 404
    assert r.json()["detail"] == "Disk sdz not found"


def test_classify_is_pure(host):
    from zboxapi import guard, system

    host.add_disk("sdc", 500 * G)
    nodes = system.block_devices()
    ps = guard.protected_set(nodes)
    states = {d.name: classify(d, ps)[0] for d in nodes}
    assert states == {"sda": "system", "sdb": "protected", "sdc": "blank"}
    assert host.mutating_calls == []


# ── rescan ───────────────────────────────────────────────────────────────────────────


def test_rescan_finds_new_disks_and_size_changes(client, host):
    host.hotplug(Disk(name="sdc", size=500 * G, serial="6000c29sdc"))
    r = client.post("/disk/rescan")
    assert r.status_code == 200, r.text
    assert r.json() == {"new": ["sdc"], "resized": []}
    assert client.get("/disk/sdc").json()["state"] == "blank"

    host.resize("sdc", T)
    r = client.post("/disk/rescan")
    assert r.json()["new"] == []
    assert r.json()["resized"] == [
        {
            "disk": "sdc",
            "before": 500 * G,
            "after": T,
            "before_human": "500.0G",
            "after_human": "1.0T",
            "storage": None,
        }
    ]
    assert client.post("/disk/rescan").json() == {"new": [], "resized": []}


def test_rescan_reads_new_sizes_of_every_disk_without_modifying_any(
    client, host, tmp_path
):
    host.resize(
        "sdb", 2 * T
    )  # grown in vSphere; a size rescan is a read, so it is seen
    host.resize("sda", 100 * G)
    r = client.post("/disk/rescan")
    assert {d["disk"]: d["after"] for d in r.json()["resized"]} == {
        "sdb": 2 * T,
        "sda": 100 * G,
    }
    assert r.json()["resized"][1]["storage"] == "STORAGE01"
    assert host.mutating_calls == []  # nothing was partitioned, formatted or mounted
    assert (
        host.disks["sdb"].parts[0].size == T - 2 * 1024**2
    )  # the partition is untouched
