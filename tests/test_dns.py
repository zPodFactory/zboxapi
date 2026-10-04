"""DNS management: hostname validation, hosts-file handling, and the /dns API."""

import io
from ipaddress import IPv4Address

import pytest
from pydantic_core import PydanticCustomError

import zboxapi.dns as dns

# ---------------------------------------------------------------------------
# validate_hostname
# ---------------------------------------------------------------------------

LABEL_63 = "a" * 63
FQDN_253 = ".".join([LABEL_63, LABEL_63, LABEL_63, "a" * 61])  # 253 chars
assert len(FQDN_253) == 253


@pytest.mark.parametrize(
    "value",
    [
        "esx01",
        "esx01.lab.local",
        "a-b.c-d",
        "ESX01.Lab.Local",
        "1",
        "1.2.3",
        "9abc",
        LABEL_63,
        FQDN_253,
    ],
)
def test_validate_hostname_accepts_valid_names(value):
    assert dns.validate_hostname(value) == value


@pytest.mark.parametrize(
    "value, message",
    [
        ("", "Invalid hostname length"),
        ("a" * 254, "Invalid hostname length"),
        ("-bad", "Invalid hostname label"),
        ("bad-", "Invalid hostname label"),
        ("under_score", "Invalid hostname label"),
        ("with space", "Invalid hostname label"),
        ("a..b", "empty label"),
        (".a", "empty label"),
        ("a.", "empty label"),
        ("a" * 64, "Invalid label length"),
        ("ok." + "a" * 64, "Invalid label length"),
    ],
)
def test_validate_hostname_rejects_invalid_names(value, message):
    with pytest.raises(PydanticCustomError, match=message):
        dns.validate_hostname(value)


# ---------------------------------------------------------------------------
# hosts file helpers
# ---------------------------------------------------------------------------

HOSTS_TEXT = """\
# comment line

192.168.1.10\tweb01 web01.lab.local
10.0.0.10   db01
10.0.0.9    db00
127.0.0.1   localhost
"""


def test_get_hosts_lines_parses_and_sorts():
    lines = dns.get_hosts_lines(io.StringIO(HOSTS_TEXT))
    assert lines == [
        {"ip": IPv4Address("127.0.0.1"), "hostname": "localhost"},
        {"ip": IPv4Address("10.0.0.9"), "hostname": "db00"},
        {"ip": IPv4Address("10.0.0.10"), "hostname": "db01"},
        {"ip": IPv4Address("192.168.1.10"), "hostname": "web01"},
        {"ip": IPv4Address("192.168.1.10"), "hostname": "web01.lab.local"},
    ]


def test_sort_hosts_lines_loopback_first_then_numeric_ip_then_hostname():
    items = [
        {"ip": IPv4Address("10.0.0.10"), "hostname": "b"},
        {"ip": IPv4Address("10.0.0.10"), "hostname": "a"},
        {"ip": IPv4Address("10.0.0.2"), "hostname": "z"},
        {"ip": IPv4Address("127.0.0.1"), "hostname": "localhost"},
    ]
    ordered = sorted(items, key=dns.sort_hosts_lines)
    assert [(str(i["ip"]), i["hostname"]) for i in ordered] == [
        ("127.0.0.1", "localhost"),
        ("10.0.0.2", "z"),
        ("10.0.0.10", "a"),
        ("10.0.0.10", "b"),
    ]


def test_filter_hosts_file_by_ip_hostname_or_both():
    lines = dns.get_hosts_lines(io.StringIO(HOSTS_TEXT))
    web = IPv4Address("192.168.1.10")
    assert len(dns.filter_hosts_file(lines)) == 5
    assert [x["hostname"] for x in dns.filter_hosts_file(lines, ip=web)] == [
        "web01",
        "web01.lab.local",
    ]
    assert dns.filter_hosts_file(lines, hostname="db01") == [
        {"ip": IPv4Address("10.0.0.10"), "hostname": "db01"}
    ]
    assert dns.filter_hosts_file(lines, web, "web01") == [
        {"ip": web, "hostname": "web01"}
    ]
    assert dns.filter_hosts_file(lines, web, "db01") == []


def test_write_hosts_file_sorts_and_overwrites():
    buf = io.StringIO("stale content that must disappear\n" * 5)
    dns.write_hosts_file(
        buf,
        [
            {"ip": IPv4Address("10.0.0.1"), "hostname": "b"},
            {"ip": IPv4Address("127.0.0.1"), "hostname": "localhost"},
            {"ip": IPv4Address("10.0.0.1"), "hostname": "a"},
        ],
    )
    assert buf.getvalue() == "127.0.0.1\tlocalhost\n10.0.0.1\ta\n10.0.0.1\tb\n"


def test_get_hosts_file_object_creates_missing_file_and_releases_lock(
    tmp_path, monkeypatch
):
    path = tmp_path / "hosts"
    monkeypatch.setattr(dns, "HOSTS_FILE", path)
    assert not path.exists()
    with dns.get_hosts_file_object() as fo:
        assert fo.read() == ""
    assert path.exists()
    # Lock must be released: a second acquisition returns immediately.
    with dns.get_hosts_file_object() as fo:
        fo.write("127.0.0.1\tlocalhost\n")
    assert path.read_text() == "127.0.0.1\tlocalhost\n"


def test_dnsmasq_sighup_sends_pkill(system):
    dns.dnsmasq_sighup()
    assert system.calls == [["pkill", "-SIGHUP", "dnsmasq"]]


# ---------------------------------------------------------------------------
# /dns API
# ---------------------------------------------------------------------------


def test_dns_get_all(client, hosts_file):
    hosts_file.write_text("10.0.0.5\tesx01\n127.0.0.1\tlocalhost\n")
    r = client.get("/dns")
    assert r.status_code == 200
    assert r.json() == [
        {"ip": "127.0.0.1", "hostname": "localhost"},
        {"ip": "10.0.0.5", "hostname": "esx01"},
    ]


def test_dns_get_one_found(client):
    r = client.get("/dns/127.0.0.1/localhost")
    assert r.status_code == 200
    assert r.json() == {"ip": "127.0.0.1", "hostname": "localhost"}


def test_dns_get_one_not_found(client):
    r = client.get("/dns/10.0.0.1/nope")
    assert r.status_code == 404
    assert "DNS record not found" in r.json()["detail"]


@pytest.mark.parametrize("path", ["/dns/999.1.1.1/host", "/dns/10.0.0.1/-bad"])
def test_dns_get_one_rejects_invalid_path_params(client, path):
    assert client.get(path).status_code == 422


def test_dns_add_record_writes_file_and_reloads_dnsmasq(client, hosts_file, system):
    r = client.post("/dns", json={"ip": "10.0.0.5", "hostname": "esx01.lab.local"})
    assert r.status_code == 200
    assert r.json() == [
        {"ip": "127.0.0.1", "hostname": "localhost"},
        {"ip": "10.0.0.5", "hostname": "esx01.lab.local"},
    ]
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n10.0.0.5\tesx01.lab.local\n"
    assert system.calls == [["pkill", "-SIGHUP", "dnsmasq"]]


def test_dns_add_duplicate_is_406(client, hosts_file, system):
    r = client.post("/dns", json={"ip": "127.0.0.1", "hostname": "localhost"})
    assert r.status_code == 406
    assert "already present" in r.json()["detail"]
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n"
    assert system.calls == []


def test_dns_add_same_ip_different_hostname_is_allowed(client):
    r = client.post("/dns", json={"ip": "127.0.0.1", "hostname": "zbox"})
    assert r.status_code == 200
    assert [x["hostname"] for x in r.json()] == ["localhost", "zbox"]


@pytest.mark.parametrize(
    "payload",
    [
        {"ip": "10.0.0.5", "hostname": "bad_host"},
        {"ip": "10.0.0.5", "hostname": "a..b"},
        {"ip": "10.0.0.5", "hostname": ""},
        {"ip": "10.0.0.300", "hostname": "ok"},
        {"ip": "::1", "hostname": "ok"},
        {"hostname": "ok"},
    ],
)
def test_dns_add_rejects_invalid_payload(client, payload, hosts_file):
    assert client.post("/dns", json=payload).status_code == 422
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n"


def test_dns_update_record(client, hosts_file, system):
    hosts_file.write_text("127.0.0.1\tlocalhost\n10.0.0.5\told\n")
    r = client.put(
        "/dns/10.0.0.5/old", json={"ip": "10.0.0.6", "hostname": "new.lab.local"}
    )
    assert r.status_code == 200
    assert r.json() == [
        {"ip": "127.0.0.1", "hostname": "localhost"},
        {"ip": "10.0.0.6", "hostname": "new.lab.local"},
    ]
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n10.0.0.6\tnew.lab.local\n"
    assert system.calls == [["pkill", "-SIGHUP", "dnsmasq"]]


def test_dns_update_missing_record_is_404(client, system):
    r = client.put("/dns/10.0.0.5/old", json={"ip": "10.0.0.6", "hostname": "new"})
    assert r.status_code == 404
    assert system.calls == []


def test_dns_update_rejects_invalid_body(client):
    r = client.put("/dns/127.0.0.1/localhost", json={"ip": "x", "hostname": "new"})
    assert r.status_code == 422


def test_dns_delete_record(client, hosts_file, system):
    hosts_file.write_text("127.0.0.1\tlocalhost\n10.0.0.5\tesx01\n")
    r = client.delete("/dns/10.0.0.5/esx01")
    assert r.status_code == 200
    assert r.json() == [{"ip": "127.0.0.1", "hostname": "localhost"}]
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n"
    assert system.calls == [["pkill", "-SIGHUP", "dnsmasq"]]


def test_dns_delete_missing_record_is_404(client, hosts_file, system):
    r = client.delete("/dns/10.0.0.5/esx01")
    assert r.status_code == 404
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n"
    assert system.calls == []


def test_dns_full_lifecycle(client, hosts_file):
    client.post("/dns", json={"ip": "10.0.0.5", "hostname": "esx01"})
    client.post("/dns", json={"ip": "10.0.0.6", "hostname": "esx02"})
    client.put("/dns/10.0.0.5/esx01", json={"ip": "10.0.0.5", "hostname": "esx-a"})
    client.delete("/dns/10.0.0.6/esx02")
    assert client.get("/dns").json() == [
        {"ip": "127.0.0.1", "hostname": "localhost"},
        {"ip": "10.0.0.5", "hostname": "esx-a"},
    ]
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n10.0.0.5\tesx-a\n"
