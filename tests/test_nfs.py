"""NFS exports, read side: merging /etc/exports, the managed file and exportfs -v."""

from tests.conftest import EXPORT_OPTS
from zboxapi import nfs

EXPORTFS_OUTPUT = """\
/FILER/STORAGE01/NFS-01
\t\t10.60.60.0/26(rw,wdelay,no_root_squash,no_subtree_check,sec=sys,rw,secure,no_root_squash,no_all_squash)
/FILER/STORAGE01/NFS-03
\t\t192.168.0.0/26(rw,wdelay,no_root_squash,no_subtree_check,sec=sys,rw,secure,no_root_squash,no_all_squash)
/FILER/STORAGE01/NFS-03
\t\t<world>(rw,wdelay,no_root_squash,no_subtree_check,sec=sys,rw,secure,no_root_squash,no_all_squash)
/srv/short     10.0.0.1(ro,wdelay,root_squash,no_subtree_check,sec=sys)
"""


def test_parse_exports_file():
    parsed = nfs.parse_exports(
        "# comment\n"
        "/FILER/STORAGE01/NFS-03 192.168.0.0/26(rw,sync) *(rw,sync) # trailing\n"
        "/FILER/STORAGE01/NFS-05 \\\n"
        "    192.168.0.0/24(rw,sync,no_subtree_check,no_root_squash)\n"
        "/bare 10.0.0.1\n"
        "\n"
    )
    assert [c.client for c in parsed["/FILER/STORAGE01/NFS-03"]] == [
        "192.168.0.0/26",
        "*",
    ]
    assert (
        parsed["/FILER/STORAGE01/NFS-05"][0].options
        == "rw,sync,no_subtree_check,no_root_squash"
    )
    assert parsed["/bare"] == [nfs.ClientView(client="10.0.0.1", options="")]


def test_parse_exportfs_v_handles_wrapped_paths_and_world():
    parsed = nfs.parse_exportfs_v(EXPORTFS_OUTPUT)
    assert [c.client for c in parsed["/FILER/STORAGE01/NFS-03"]] == [
        "192.168.0.0/26",
        "*",
    ]
    assert parsed["/FILER/STORAGE01/NFS-01"][0].client == "10.60.60.0/26"
    assert parsed["/srv/short"][0].client == "10.0.0.1"
    assert parsed["/srv/short"][0].options.startswith("ro,")


def test_nfs_get_all_merges_system_managed_and_active(client, host, filer, tmp_path):
    managed = tmp_path / "etc" / "exports.d" / "zboxapi.exports"
    (filer / "STORAGE01" / "NFS-06").mkdir()
    managed.write_text(
        f"{filer}/STORAGE01/NFS-06 10.60.60.0/26({EXPORT_OPTS})\n"
        f"{filer}/STORAGE01/NFS-GONE 10.60.60.0/26({EXPORT_OPTS})\n"
    )
    host.reload_exports()
    host.active_exports.pop(
        f"{filer}/STORAGE01/NFS-GONE"
    )  # in the file, not exported live

    r = client.get("/nfs")
    assert r.status_code == 200
    by = {e["path"]: e for e in r.json()}
    assert len(by) == 8

    nfs01 = by[f"{filer}/STORAGE01/NFS-01"]
    assert nfs01["owner"] == "system" and nfs01["protected"] is True
    assert nfs01["storage"] == "STORAGE01" and nfs01["folder"] == "NFS-01"
    assert nfs01["active"] is True and nfs01["folder_exists"] is True
    assert nfs01["clients"] == [
        {
            "client": "10.60.60.0/26",
            "options": "rw,sync,no_subtree_check,no_root_squash",
        }
    ]
    assert [c["client"] for c in by[f"{filer}/STORAGE01/NFS-03"]["clients"]] == [
        "192.168.0.0/26",
        "*",
    ]
    nfs06 = by[f"{filer}/STORAGE01/NFS-06"]
    assert nfs06["owner"] == "user-defined" and nfs06["protected"] is False
    assert nfs06["active"] is True
    gone = by[f"{filer}/STORAGE01/NFS-GONE"]
    assert gone["active"] is False and gone["folder_exists"] is False


def test_nfs_get_one_and_404(client, host, filer):
    r = client.get("/nfs/STORAGE01/NFS-02")
    assert r.status_code == 200
    assert r.json()["path"] == f"{filer}/STORAGE01/NFS-02"
    r = client.get("/nfs/STORAGE01/NFS-99")
    assert r.status_code == 404


def test_export_outside_the_convention_is_listed_without_storage(
    client, host, tmp_path
):
    etc = tmp_path / "etc"
    (etc / "exports").write_text("/srv/iso *(ro,sync,no_subtree_check)\n")
    host.reload_exports()
    [e] = client.get("/nfs").json()
    assert e["path"] == "/srv/iso" and e["storage"] is None and e["folder"] is None
    assert e["clients"] == [{"client": "*", "options": "ro,sync,no_subtree_check"}]


def test_system_file_wins_over_a_duplicate_in_the_managed_file(
    client, host, filer, tmp_path
):
    managed = tmp_path / "etc" / "exports.d" / "zboxapi.exports"
    managed.write_text(f"{filer}/STORAGE01/NFS-02 *(rw)\n")
    e = client.get("/nfs/STORAGE01/NFS-02").json()
    assert e["owner"] == "system"
    assert e["clients"][0]["client"] == "10.60.60.0/26"
