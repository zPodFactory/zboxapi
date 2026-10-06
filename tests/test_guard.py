"""The protected set and its three enforcement points."""

import pytest

from tests.conftest import ME
from tests.fake_host import G, T
from zboxapi import guard, system


def test_protected_set_resolves_from_the_live_mount(host, filer):
    ps = guard.protected_set()
    assert ps.storages == {"STORAGE01"}
    assert ps.mountpoints == {str(filer / "STORAGE01")}
    assert {"sdb", "/dev/sdb", "sdb1", "/dev/sdb1"} <= ps.devices


def test_system_disk_is_in_the_protected_set(host, filer):
    # zbox layout: /boot on sda1, root on vg/root over sda5
    sda = host.disks["sda"]
    sda.parts[0].mountpoint = "/boot"
    host.add_part("sda", 40 * G)
    host.add_lv("vg", "root", "sda2", mountpoint="/")
    ps = guard.protected_set()
    assert {"sda", "/dev/sda", "sda1", "sda2", "/dev/sda2"} <= ps.devices
    assert "vg" in ps.vgs
    assert {"/dev/vg/root", "/dev/mapper/vg-root"} <= ps.devices
    assert (
        "/" not in ps.mountpoints
    )  # paths under / are not protected, only the devices
    assert ps.reason_for("sda") == "sda is the system disk: never modified"
    assert guard.protected_set().reason_for("/etc/hosts") is None
    assert str(filer / "STORAGE01" / "NFS-01") in ps.exports
    assert "/FILER/STORAGE01/NFS-01" in ps.exports  # the literal floor, always present


def test_protected_set_follows_the_mount_not_the_letter(host, filer):
    # A disk order change: what was sdb is now sdc, the mount is what matters.
    disk = host.disks.pop("sdb")
    disk.name = "sdc"
    for p in disk.parts:
        p.name = "sdc1"
    host.disks["sdc"] = disk
    ps = guard.protected_set()
    assert {"sdc", "/dev/sdc", "sdc1", "/dev/sdc1"} <= ps.devices
    assert "sdb" not in ps.devices


def test_protected_set_covers_lvm_on_the_protected_disk(host, filer):
    # If STORAGE01 were on LVM, the VG and the LV paths are protected too.
    part = host.disks["sdb"].parts[0]
    part.mountpoint = None
    host.add_lv("vg_storage01", "data", "sdb1", mountpoint=str(filer / "STORAGE01"))
    ps = guard.protected_set()
    assert "vg_storage01" in ps.vgs
    assert {"/dev/vg_storage01/data", "/dev/mapper/vg_storage01-data"} <= ps.devices
    assert ps.reason_for("vg_storage01/data") is None  # bare vg/lv is matched via run()
    assert ps.reason_for("/dev/vg_storage01/data")


def test_config_cannot_remove_the_floor(host, filer, tmp_path):
    (tmp_path / "etc" / "zboxapi.conf").write_text(
        f"[storage]\nfiler_root = {filer}\nprotected_storages =\n"
        "[nfs]\nprotected_exports =\n"
        f"system_exports_file = {tmp_path / 'etc' / 'exports'}\n"
    )
    ps = guard.protected_set()
    assert "STORAGE01" in ps.storages
    assert (
        "/FILER/STORAGE01/NFS-01" in ps.exports
    )  # the floor is the literal default path


def test_config_can_add_to_the_set(host, filer, tmp_path):
    (tmp_path / "etc" / "zboxapi.conf").write_text(
        f"[storage]\nfiler_root = {filer}\nprotected_storages = STORAGE01, STORAGE09\n"
    )
    assert "STORAGE09" in guard.protected_set().storages


@pytest.mark.parametrize(
    "target",
    [
        "sdb",
        "/dev/sdb",
        "sdb1",
        "/dev/sdb1",
        "STORAGE01",
        "{filer}/STORAGE01",
        "{filer}/STORAGE01/",
        "{filer}/STORAGE01/NFS-01",
        "{filer}/STORAGE01/NFS-01/vm-esx01",
    ],
)
def test_assert_mutable_refuses_protected_targets(host, filer, target):
    with pytest.raises(guard.ProtectedError):
        guard.assert_mutable(target.format(filer=filer))


@pytest.mark.parametrize(
    "target",
    [
        "/dev/sdc",
        "STORAGE02",
        "{filer}/STORAGE02",
        "{filer}/STORAGE010",
        "{filer}/STORAGE01x",
        "{filer}/STORAGE01/NFS-02",  # other folders on STORAGE01 are manageable
        "{filer}/STORAGE01/NFS-010",
    ],
)
def test_assert_mutable_allows_everything_else(host, filer, target):
    guard.assert_mutable(target.format(filer=filer))


@pytest.mark.parametrize(
    "argv",
    [
        ["sgdisk", "--zap-all", "/dev/sdb"],
        ["mkfs.ext4", "/dev/sdb1"],
        ["umount", "{filer}/STORAGE01"],
        ["rm", "-rf", "{filer}/STORAGE01/NFS-01"],
        ["wipefs", "-a", "/dev/sdb1"],
        ["sysfs-write", "/sys/class/block/sdb/device/scan"],
        ["systemd-mount", "What=/dev/sdb1"],
        ["mkfs.ext4", "/dev/sda1"],
        ["sgdisk", "--zap-all", "/dev/sda"],
        [
            "resize2fs",
            "/dev/sdb1",
            "10G",
        ],  # a size argument can shrink: not extend-only
        ["pvresize", "--setphysicalvolumesize", "10G", "/dev/sdb1"],
        ["growpart", "/dev/sdb", "1", "--dry-run"],  # only the exact shape is allowed
    ],
)
def test_run_refuses_any_argv_naming_a_protected_member(host, filer, argv):
    argv = [a.format(filer=filer) for a in argv]
    with pytest.raises(guard.ProtectedError, match="refused to run"):
        system.run(argv)
    assert host.mutating_calls == []
    assert not any(c[0] == argv[0] for c in host.calls)


@pytest.mark.parametrize(
    "argv",
    [
        ["growpart", "/dev/sdb", "1"],
        ["pvresize", "/dev/sdb1"],
        ["lvextend", "-l", "+100%FREE", "/dev/vg_storage01/data"],
        ["resize2fs", "/dev/sdb1"],
        ["sysfs-write", "/sys/class/block/sdb/device/rescan"],
    ],
)
def test_run_allows_extend_only_commands_on_protected_devices(host, argv):
    """Growing adds space and moves no data: the one thing a protected disk allows."""
    assert guard.is_extend_only(argv)
    guard.assert_argv_allowed(argv)  # does not raise


def test_run_lets_read_only_commands_name_protected_devices(host):
    result = system.query(["lsblk", "-J", "-b", "/dev/sdb"])
    assert result.returncode == 0


def test_query_refuses_mutating_commands(host):
    with pytest.raises(ValueError, match="not a read-only"):
        system.query(["mkfs.ext4", "/dev/sdc1"])


def test_run_audits_commands(host, tmp_path, monkeypatch):
    host.add_disk("sdc", 500 * G)
    # exportfs -ra is the only mutating command the model knows in phase 1
    system.run(["exportfs", "-ra"], source="test")
    log = (tmp_path / "audit.log").read_text()
    assert "test rc=0 exportfs -ra" in log


def test_lvm_on_protected_disk_blocks_vg_lv_argv(host, filer):
    part = host.disks["sdb"].parts[0]
    part.mountpoint = None
    host.add_lv("vg_storage01", "data", "sdb1", mountpoint=str(filer / "STORAGE01"))
    for argv in (
        ["lvreduce", "-L", "-10G", "vg_storage01/data"],
        ["lvremove", "-y", "/dev/vg_storage01/data"],
        ["vgremove", "vg_storage01"],
        ["resize2fs", "/dev/mapper/vg_storage01-data", "100G"],
    ):
        with pytest.raises(guard.ProtectedError):
            system.run(argv)


# ── the protection matrix: every mutating endpoint against every protected target ──


@pytest.mark.parametrize(
    "method, path, body",
    [
        ("POST", "/storage", {"disk": "sdb"}),
        ("POST", "/storage", {"disk": "sda"}),
        ("POST", "/storage/adopt", {"device": "sdb1"}),
        ("POST", "/storage/adopt", {"device": "sda1"}),
        ("DELETE", "/storage/STORAGE01", None),
        ("POST", "/storage/STORAGE01/NFS-01", {}),
        ("PUT", "/storage/STORAGE01/NFS-01", {"mode": "0755"}),
        ("DELETE", "/storage/STORAGE01/NFS-01", None),
        ("DELETE", "/storage/STORAGE01/NFS-01?force=true", None),
        (
            "POST",
            "/nfs",
            {"storage": "STORAGE01", "folder": "NFS-01", "clients": ["*"]},
        ),
        ("PUT", "/nfs/STORAGE01/NFS-01", {"clients": ["*"]}),
        ("POST", "/nfs/STORAGE01/NFS-01/client", {"client": "*"}),
        ("DELETE", "/nfs/STORAGE01/NFS-01/client/10.60.60.0/26", None),
        ("DELETE", "/nfs/STORAGE01/NFS-01", None),
        ("POST", "/disk/sdb/detach", None),
        ("POST", "/disk/sda/detach", None),
    ],
)
def test_matrix_protected_targets_get_403_and_nothing_runs(
    client, host, filer, method, path, body
):
    before = host.snapshot("sdb"), host.snapshot("sda")
    nfs01 = sorted(str(p) for p in (filer / "STORAGE01" / "NFS-01").rglob("*"))
    r = client.request(method, path, json=body)
    assert r.status_code == 403, (method, path, r.text)
    assert host.mutating_calls == []
    assert (host.snapshot("sdb"), host.snapshot("sda")) == before
    assert sorted(str(p) for p in (filer / "STORAGE01" / "NFS-01").rglob("*")) == nfs01


def test_grow_is_the_one_operation_a_protected_storage_allows(client, host, filer):
    host.resize("sdb", 2 * T)
    r = client.post("/storage/STORAGE01/grow?verbose=true")
    assert r.status_code == 200, r.text
    assert r.json()["changed"] is True
    assert r.json()["after"]["partition_bytes"] == 2 * T - 2 * 1024**2
    part = host.disks["sdb"].parts[0]
    assert part.fstype == "ext4" and part.uuid == "bbbb-storage01"  # same filesystem
    assert part.mountpoint == str(filer / "STORAGE01")  # never unmounted
    assert all(guard.is_extend_only(c) for c in host.mutating_calls)


def test_grow_failure_on_protected_storage_changes_nothing(client, host, filer):
    host.resize("sdb", 2 * T)
    host.fail.add(("growpart",))
    before = host.snapshot("sdb", sizes=False)
    r = client.post("/storage/STORAGE01/grow")
    assert r.status_code == 500
    detail = r.json()["detail"]
    assert detail["message"].startswith(
        "Cannot grow STORAGE01: growpart on /dev/sdb1 failed"
    )
    assert {s["step"]: s.get("exit_code") for s in detail["steps"]} == {
        "rescan": None,
        "growpart": 2,
        "resize2fs": None,
    }
    assert "The data is untouched" in detail["message"]
    assert detail["rollback"] == []
    assert host.snapshot("sdb", sizes=False) == before
    assert host.disks["sdb"].parts[0].size == T - 2 * 1024**2  # partition not grown


def test_invariants_hold_across_random_call_sequences(client, host, filer, tmp_path):
    """A few hundred valid and invalid calls in random order: sdb, /etc/exports and
    NFS-01 end exactly as they started."""
    import random

    from tests.fake_host import Disk

    rng = random.Random(4)
    etc = tmp_path / "etc"
    seed_sdb = host.snapshot("sdb", sizes=False)
    seed_sizes = host.sizes("sdb")
    seed_nfs01_export = host.active_exports[str(filer / "STORAGE01" / "NFS-01")]
    seed_exports = (etc / "exports").read_text()
    seed_nfs01 = sorted(str(p) for p in (filer / "STORAGE01" / "NFS-01").rglob("*"))
    host.hotplug(Disk(name="sdc", size=500 * G, serial="c"))
    host.hotplug(Disk(name="sdd", size=T, serial="d"))

    actions = [
        lambda: client.post("/disk/rescan"),
        lambda: client.post(
            "/storage",
            json={
                "disk": rng.choice(["sda", "sdb", "sdc", "sdd", "sdz"]),
                "lvm": rng.random() < 0.5,
            },
        ),
        lambda: client.post(
            "/storage/adopt",
            json={"device": rng.choice(["sdb1", "sda1", "sdc1", "sdd1"])},
        ),
        lambda: client.post(
            f"/storage/{rng.choice(['STORAGE01', 'STORAGE02', 'STORAGE03'])}/grow"
        ),
        lambda: client.delete(
            f"/storage/{rng.choice(['STORAGE01', 'STORAGE02', 'STORAGE03'])}"
        ),
        lambda: client.post(
            f"/storage/{rng.choice(['STORAGE01', 'STORAGE02'])}/folder",
            json={
                "name": rng.choice(["NFS-01", "NFS-06", "x"]),
                "owner": ME,
                "mode": "0777",
            },
        ),
        lambda: client.put(
            f"/storage/STORAGE01/{rng.choice(['NFS-01', 'NFS-02'])}",
            json={"mode": "0700", "recursive": True},
        ),
        lambda: client.delete(
            f"/storage/STORAGE01/{rng.choice(['NFS-01', 'NFS-02', 'NFS-06'])}"
            f"?force={rng.choice(['true', 'false'])}"
        ),
        lambda: (host.resize(rng.choice(["sdb", "sdc", "sdd"]), 2 * T), None)[1],
        lambda: client.post(
            "/nfs",
            json={
                "storage": rng.choice(["STORAGE01", "STORAGE02", "STORAGE03"]),
                "folder": rng.choice(["NFS-01", "NFS-02", "NFS-06", "NFS-15"]),
                "clients": [rng.choice(["*", "10.60.60.0/26", "bogus"])],
            },
        ),
        lambda: client.put(
            f"/nfs/STORAGE01/{rng.choice(['NFS-01', 'NFS-02', 'NFS-06'])}",
            json={"clients": ["192.168.0.0/24"]},
        ),
        lambda: client.delete(
            f"/nfs/{rng.choice(['STORAGE01', 'STORAGE02'])}"
            f"/{rng.choice(['NFS-01', 'NFS-02', 'NFS-06', 'NFS-15'])}"
        ),
        lambda: client.delete(
            f"/nfs/STORAGE01/{rng.choice(['NFS-01', 'NFS-06'])}/client/10.60.60.0/26"
        ),
        lambda: client.post(f"/disk/{rng.choice(['sda', 'sdb', 'sdc', 'sdd'])}/detach"),
        lambda: client.put(
            f"/nfs/STORAGE01/{rng.choice(['NFS-01', 'NFS-02', 'NFS-06'])}",
            json={"clients": ["*"]},
        ),
    ]
    for _ in range(300):
        rng.choice(actions)()
    # sdb may only have grown: same layout, labels, UUIDs and mount, sizes never smaller
    assert "sdb" in host.disks and "sda" in host.disks  # never detached
    assert host.snapshot("sdb", sizes=False) == seed_sdb
    assert all(a >= b for a, b in zip(host.sizes("sdb"), seed_sizes, strict=True))
    assert (etc / "exports").read_text() == seed_exports
    assert (
        sorted(str(p) for p in (filer / "STORAGE01" / "NFS-01").rglob("*"))
        == seed_nfs01
    )
    assert host.active_exports[str(filer / "STORAGE01" / "NFS-01")] == seed_nfs01_export
    sdb_cmds = [c for c in host.mutating_calls if any("sdb" in a for a in c)]
    assert all(guard.is_extend_only(c) for c in sdb_cmds), sdb_cmds
    assert not any(any("sda" in a for a in c) for c in host.mutating_calls)
