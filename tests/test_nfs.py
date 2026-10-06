"""NFS exports, read side: merging /etc/exports, the managed file and exportfs -v."""

import pytest

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
            "options": EXPORT_OPTS,
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


# ── create, update, clients, delete ──────────────────────────────────────────────────


def managed(tmp_path):
    return (tmp_path / "etc" / "exports.d" / "zboxapi.exports").read_text()


def test_export_create_makes_the_folder_and_reloads(client, host, filer, tmp_path):
    host.mutating_calls.clear()
    r = client.post(
        "/nfs",
        json={"storage": "STORAGE01", "folder": "NFS-06", "clients": ["10.60.60.0/26"]},
    )
    assert r.status_code == 200, r.text
    assert r.json() == {
        "path": f"{filer}/STORAGE01/NFS-06",
        "storage": "STORAGE01",
        "folder": "NFS-06",
        "clients": [{"client": "10.60.60.0/26", "options": EXPORT_OPTS}],
        "owner": "user-defined",
        "protected": False,
        "active": True,
        "folder_exists": True,
    }
    folder = filer / "STORAGE01" / "NFS-06"
    assert folder.is_dir() and oct(folder.stat().st_mode & 0o7777) == "0o777"
    assert managed(tmp_path).splitlines()[-1] == (
        f"{filer}/STORAGE01/NFS-06 10.60.60.0/26({EXPORT_OPTS})"
    )
    assert host.mutating_calls == [["exportfs", "-ra"]]
    assert host.active_exports[f"{filer}/STORAGE01/NFS-06"] == ["10.60.60.0/26"]
    log = (tmp_path / "audit.log").read_text()
    assert "nfs_create rc=0 export " in log and "exportfs -ra" in log


def test_export_create_on_a_new_storage_with_several_clients(
    client, host, filer, tmp_path
):
    from tests.fake_host import G

    host.add_disk("sdd", 2 * G * 1024)
    assert (
        client.post("/storage", json={"disk": "sdd", "name": "STORAGE03"}).status_code
        == 200
    )
    r = client.post(
        "/nfs",
        json={
            "storage": "STORAGE03",
            "folder": "NFS-20",
            "clients": ["192.168.0.0/24", "10.60.60.10", "*"],
        },
    )
    assert r.status_code == 200, r.text
    assert [c["client"] for c in r.json()["clients"]] == [
        "192.168.0.0/24",
        "10.60.60.10",
        "*",
    ]
    assert (filer / "STORAGE03" / "NFS-20").is_dir()
    assert "*(" in managed(tmp_path)
    assert client.get("/storage/STORAGE03").json()["exports"] == 1
    assert client.get("/storage/STORAGE03").json()["folders"][0]["exported"] is True


def test_export_create_keeps_an_existing_folder(client, host, filer):
    (filer / "STORAGE01" / "NFS-06").mkdir(mode=0o750)
    (filer / "STORAGE01" / "NFS-06" / "keep").write_text("x")
    r = client.post(
        "/nfs", json={"storage": "STORAGE01", "folder": "NFS-06", "clients": ["*"]}
    )
    assert r.status_code == 200, r.text
    assert (filer / "STORAGE01" / "NFS-06" / "keep").exists()
    assert oct((filer / "STORAGE01" / "NFS-06").stat().st_mode & 0o7777) == "0o750"


@pytest.mark.parametrize(
    "payload, code, message",
    [
        (
            {"storage": "STORAGE01", "folder": "NFS-02", "clients": ["*"]},
            403,
            "owner system",
        ),
        (
            {"storage": "STORAGE01", "folder": "NFS-01", "clients": ["*"]},
            403,
            "protected",
        ),
        ({"storage": "STORAGE09", "folder": "x", "clients": ["*"]}, 400, "not mounted"),
        ({"storage": "STORAGE01", "folder": "x", "clients": []}, 422, "at least 1"),
        (
            {"storage": "STORAGE01", "folder": "x", "clients": ["10.0.0.0/33"]},
            422,
            "Invalid client",
        ),
        (
            {"storage": "STORAGE01", "folder": "x", "clients": ["host.example"]},
            422,
            "Invalid client",
        ),
        (
            {"storage": "STORAGE01", "folder": "x", "clients": ["::1"]},
            422,
            "Invalid client",
        ),
        (
            {"storage": "STORAGE01", "folder": "x", "clients": ["*", "*"]},
            422,
            "Duplicate client",
        ),
        (
            {"storage": "STORAGE01", "folder": "a/b", "clients": ["*"]},
            422,
            "Invalid folder name",
        ),
        ({"storage": "STORAGE01", "folder": "grow", "clients": ["*"]}, 422, "reserved"),
        (
            {"storage": "storage01", "folder": "x", "clients": ["*"]},
            422,
            "Invalid storage name",
        ),
    ],
)
def test_export_create_refusals(client, host, filer, tmp_path, payload, code, message):
    r = client.post("/nfs", json=payload)
    assert r.status_code == code, (payload, r.text)
    assert message in r.text, (payload, r.text)
    assert host.mutating_calls == []
    assert not (filer / "STORAGE01" / "x").exists()


def test_export_create_twice_is_409(client, host, filer):
    body = {"storage": "STORAGE01", "folder": "NFS-06", "clients": ["*"]}
    assert client.post("/nfs", json=body).status_code == 200
    r = client.post("/nfs", json=body)
    assert r.status_code == 409 and "already exported" in r.json()["detail"]


def test_export_update_replaces_clients(client, host, filer, tmp_path):
    body = {"storage": "STORAGE01", "folder": "NFS-06", "clients": ["10.60.60.0/26"]}
    assert client.post("/nfs", json=body).status_code == 200
    r = client.put("/nfs/STORAGE01/NFS-06", json={"clients": ["192.168.0.0/24", "*"]})
    assert r.status_code == 200, r.text
    assert [c["client"] for c in r.json()["clients"]] == ["192.168.0.0/24", "*"]
    assert host.active_exports[f"{filer}/STORAGE01/NFS-06"] == ["192.168.0.0/24", "*"]
    assert client.put("/nfs/STORAGE01/NFS-06", json={"clients": []}).status_code == 422
    r = client.put("/nfs/STORAGE01/NFS-99", json={"clients": ["*"]})
    assert r.status_code == 201  # PUT creates what is missing


def test_export_clients_add_and_remove(client, host, filer, tmp_path):
    body = {"storage": "STORAGE01", "folder": "NFS-06", "clients": ["10.60.60.0/26"]}
    assert client.post("/nfs", json=body).status_code == 200

    r = client.post("/nfs/STORAGE01/NFS-06/client", json={"client": "192.168.0.0/24"})
    assert r.status_code == 200, r.text
    assert [c["client"] for c in r.json()["clients"]] == [
        "10.60.60.0/26",
        "192.168.0.0/24",
    ]

    r = client.post("/nfs/STORAGE01/NFS-06/client", json={"client": "192.168.0.0/24"})
    assert r.status_code == 409 and "already a client" in r.json()["detail"]
    r = client.post("/nfs/STORAGE01/NFS-06/client", json={"client": "10.0.0.0/33"})
    assert r.status_code == 422

    r = client.delete("/nfs/STORAGE01/NFS-06/client/10.60.60.0%2F26")
    assert r.status_code == 200, r.text
    assert [c["client"] for c in r.json()["clients"]] == ["192.168.0.0/24"]
    r = client.delete(
        "/nfs/STORAGE01/NFS-06/client/10.60.60.0/26"
    )  # unencoded works too
    assert r.status_code == 404 and "is not a client" in r.json()["detail"]

    # removing the last client removes the export, the folder stays
    r = client.delete("/nfs/STORAGE01/NFS-06/client/192.168.0.0/24")
    assert r.status_code == 200, r.text
    assert r.json()["folder_kept"] is True and "last client" in r.json()["message"]
    assert f"{filer}/STORAGE01/NFS-06" not in managed(tmp_path)
    assert f"{filer}/STORAGE01/NFS-06" not in host.active_exports
    assert (filer / "STORAGE01" / "NFS-06").is_dir()
    assert client.get("/nfs/STORAGE01/NFS-06").status_code == 404


def test_export_delete_keeps_the_folder_and_its_data(client, host, filer, tmp_path):
    body = {"storage": "STORAGE01", "folder": "NFS-06", "clients": ["*"]}
    assert client.post("/nfs", json=body).status_code == 200
    (filer / "STORAGE01" / "NFS-06" / "vm-a").mkdir()
    (filer / "STORAGE01" / "NFS-06" / "vm-a" / "disk.vmdk").write_text("x")
    host.mutating_calls.clear()

    r = client.delete("/nfs/STORAGE01/NFS-06")
    assert r.status_code == 200, r.text
    assert r.json() == {
        "message": f"{filer}/STORAGE01/NFS-06 is no longer exported; "
        "the folder and its data stay",
        "path": f"{filer}/STORAGE01/NFS-06",
        "folder_kept": True,
    }
    assert (filer / "STORAGE01" / "NFS-06" / "vm-a" / "disk.vmdk").exists()
    assert host.mutating_calls == [["exportfs", "-ra"]]
    assert f"{filer}/STORAGE01/NFS-06" not in managed(tmp_path)
    assert client.delete("/nfs/STORAGE01/NFS-06").status_code == 404

    # now the folder can go, with force since it has data
    assert client.delete("/storage/STORAGE01/NFS-06").status_code == 409
    assert client.delete("/storage/STORAGE01/NFS-06?force=true").status_code == 200


@pytest.mark.parametrize(
    "method, path, body",
    [
        ("PUT", "/nfs/STORAGE01/NFS-01", {"clients": ["*"]}),
        ("POST", "/nfs/STORAGE01/NFS-01/client", {"client": "*"}),
        ("DELETE", "/nfs/STORAGE01/NFS-01/client/10.60.60.0/26", None),
        ("DELETE", "/nfs/STORAGE01/NFS-01", None),
        ("PUT", "/nfs/STORAGE01/NFS-02", {"clients": ["*"]}),
        ("POST", "/nfs/STORAGE01/NFS-02/client", {"client": "*"}),
        ("DELETE", "/nfs/STORAGE01/NFS-02/client/10.60.60.0/26", None),
        ("DELETE", "/nfs/STORAGE01/NFS-VCD", None),
    ],
)
def test_system_and_protected_exports_are_never_modified(
    client, host, filer, tmp_path, method, path, body
):
    before = (tmp_path / "etc" / "exports").read_text()
    r = client.request(method, path, json=body)
    assert r.status_code == 403, (method, path, r.text)
    assert (tmp_path / "etc" / "exports").read_text() == before
    assert not (tmp_path / "etc" / "exports.d" / "zboxapi.exports").exists()
    assert host.mutating_calls == []


def test_managed_file_is_replaced_atomically(
    client, host, filer, tmp_path, monkeypatch
):
    import os as _os

    replaced = []
    real_replace = _os.replace
    monkeypatch.setattr(
        nfs.os, "replace", lambda a, b: (replaced.append(b), real_replace(a, b))
    )
    target = tmp_path / "etc" / "exports.d" / "zboxapi.exports"
    body = {"storage": "STORAGE01", "folder": "NFS-06", "clients": ["*"]}
    assert client.post("/nfs", json=body).status_code == 200
    assert replaced == [target]
    assert not [
        p for p in target.parent.iterdir() if p.name.startswith(".")
    ]  # no temp left
    assert oct(target.stat().st_mode & 0o777) == "0o644"
    assert target.read_text().startswith("# Managed by zboxapi")


def test_managed_file_round_trips_through_the_parser(client, host, filer, tmp_path):
    for folder, clients in (("A", ["*"]), ("B", ["10.0.0.1", "10.0.1.0/24"])):
        r = client.post(
            "/nfs", json={"storage": "STORAGE01", "folder": folder, "clients": clients}
        )
        assert r.status_code == 200, r.text
    parsed = nfs.parse_exports(managed(tmp_path))
    assert {
        p.rsplit("/", 1)[1]: [c.client for c in cs] for p, cs in parsed.items()
    } == {
        "A": ["*"],
        "B": ["10.0.0.1", "10.0.1.0/24"],
    }
    assert all(c.options == EXPORT_OPTS for cs in parsed.values() for c in cs)


# ── upsert, status ───────────────────────────────────────────────────────────────────


def test_put_creates_when_missing_and_is_idempotent(client, host, filer, tmp_path):
    body = {"clients": ["10.60.60.0/26"]}
    r = client.put("/nfs/STORAGE01/NFS-06", json=body)
    assert r.status_code == 201, r.text
    assert (filer / "STORAGE01" / "NFS-06").is_dir()
    assert [c["client"] for c in r.json()["clients"]] == ["10.60.60.0/26"]

    r = client.put("/nfs/STORAGE01/NFS-06", json=body)  # same call again
    assert r.status_code == 200, r.text
    assert [c["client"] for c in r.json()["clients"]] == ["10.60.60.0/26"]
    assert managed(tmp_path).count("NFS-06") == 1  # one line, not two

    r = client.put("/nfs/STORAGE01/NFS-06", json={"clients": ["*"]})
    assert r.status_code == 200 and [c["client"] for c in r.json()["clients"]] == ["*"]

    r = client.put("/nfs/STORAGE09/NFS-06", json=body)
    assert r.status_code == 400 and "not mounted" in r.json()["detail"]
    assert client.put("/nfs/STORAGE01/NFS-01", json=body).status_code == 403
    assert client.put("/nfs/STORAGE01/NFS-02", json=body).status_code == 403


def test_nfs_status(client, host, filer, tmp_path):
    host.v3_mounts = [("10.60.60.11", f"{filer}/STORAGE01/NFS-01")]
    info = tmp_path / "proc" / "fs" / "nfsd" / "clients" / "7" / "info"
    info.parent.mkdir()
    info.write_text(
        'clientid: 0x1\naddress: "10.60.60.12:812"\nstatus: confirmed\n'
        "name: Linux NFSv4.1 esx02\nminor version: 1\n"
    )
    (tmp_path / "etc" / "exports.d" / "zboxapi.exports").write_text(
        f"{filer}/STORAGE01/NFS-GONE *({EXPORT_OPTS})\n"
    )  # in a file, not reloaded: inactive

    r = client.get("/nfs/status")
    assert r.status_code == 200, r.text
    assert r.json() == {
        "service": "active",
        "enabled": True,
        "versions": ["3", "4", "4.1", "4.2"],
        "threads": 8,
        "exports": 6,
        "exports_in_files": 7,
        "inactive_exports": [f"{filer}/STORAGE01/NFS-GONE"],
        "clients": [
            {
                "client": "10.60.60.11",
                "path": f"{filer}/STORAGE01/NFS-01",
                "version": "3",
            },
            {"client": "10.60.60.12:812", "path": None, "version": "4.1"},
        ],
    }
    host.nfs_state = "inactive"
    assert client.get("/nfs/status").json()["service"] == "inactive"
