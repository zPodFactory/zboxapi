"""The protected set and its three enforcement points."""

import pytest

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
        ["growpart", "/dev/sdb", "1"],
        ["sgdisk", "--zap-all", "/dev/sdb"],
        ["mkfs.ext4", "/dev/sdb1"],
        ["umount", "{filer}/STORAGE01"],
        ["rm", "-rf", "{filer}/STORAGE01/NFS-01"],
        ["wipefs", "-a", "/dev/sdb1"],
        ["sysfs-write", "/sys/class/block/sdb/device/rescan"],
        ["systemd-mount", "What=/dev/sdb1"],
        ["growpart", "/dev/sda", "1"],
        ["mkfs.ext4", "/dev/sda1"],
        ["sgdisk", "--zap-all", "/dev/sda"],
        ["sysfs-write", "/sys/class/block/sda/device/rescan"],
    ],
)
def test_run_refuses_any_argv_naming_a_protected_member(host, filer, argv):
    argv = [a.format(filer=filer) for a in argv]
    with pytest.raises(guard.ProtectedError, match="refused to run"):
        system.run(argv)
    assert host.mutating_calls == []
    assert not any(c[0] == argv[0] for c in host.calls)


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
        ["lvextend", "-l", "+100%FREE", "vg_storage01/data"],
        ["lvextend", "-l", "+100%FREE", "/dev/vg_storage01/data"],
        ["vgremove", "vg_storage01"],
        ["resize2fs", "/dev/mapper/vg_storage01-data"],
    ):
        with pytest.raises(guard.ProtectedError):
            system.run(argv)


def test_sizes_are_what_duf_prints():
    assert system.human_size(T - 2 * 1024**2) == "1024.0G"
    assert system.human_size(1006_9 * 1024**3 // 10) == "1006.9G"
    assert system.human_size(28 * 1024) == "28.0K"
    assert system.human_size(512) == "512B"
