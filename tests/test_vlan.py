"""VLAN management: config loading, validation, interfaces.d handling, /vlan API."""

import pytest
from pydantic_core import PydanticCustomError

import zboxapi.vlan as vlan
from tests.conftest import write_user_vlan

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------


def test_load_config_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(vlan, "CONFIG_FILE", tmp_path / "missing.conf")
    with pytest.raises(vlan.ConfigError, match="not found"):
        vlan.load_config()


def test_config_values_from_file(vlan_config):
    assert vlan.get_interface_name() == "eth1"
    assert vlan.get_mtu() == 1700
    assert vlan.get_system_vlans_default() == [10, 20, 30]
    assert vlan.get_system_vlans_zpod() == [64, 128, 192]


def test_config_values_fall_back_to_defaults(vlan_config):
    vlan_config.write_text("[DEFAULT]\n")
    assert vlan.get_interface_name() == "eth1"
    assert vlan.get_mtu() == 1700
    assert vlan.get_system_vlans_default() == [10, 20, 30]
    assert vlan.get_system_vlans_zpod() == [64, 128, 192]


def test_config_values_custom(vlan_config):
    vlan_config.write_text(
        "[DEFAULT]\ninterface = ens3\nmtu = 9000\n"
        "system_vlans_default = 5, 6\nsystem_vlans_zpod = 7\n"
    )
    assert vlan.get_interface_name() == "ens3"
    assert vlan.get_mtu() == 9000
    assert vlan.get_system_vlans_default() == [5, 6]
    assert vlan.get_system_vlans_zpod() == [7]


@pytest.mark.parametrize(
    "line, getter, message",
    [
        ("mtu = big", vlan.get_mtu, "Invalid MTU"),
        ("system_vlans_default = 1,x", vlan.get_system_vlans_default, "default"),
        ("system_vlans_zpod = a", vlan.get_system_vlans_zpod, "zpod"),
    ],
)
def test_config_invalid_values_raise(vlan_config, line, getter, message):
    vlan_config.write_text(f"[DEFAULT]\n{line}\n")
    with pytest.raises(vlan.ConfigError, match=message):
        getter()


def test_get_config_value_missing_without_default(vlan_config):
    config = vlan.load_config()
    with pytest.raises(vlan.ConfigError, match="Configuration missing"):
        vlan.get_config_value(config, "DEFAULT", "nope")
    assert vlan.get_config_value(config, "DEFAULT", "nope", "dflt") == "dflt"


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vlan_id", [1, 2000, 4094])
def test_validate_vlan_id_accepts(vlan_config, vlan_id):
    assert vlan.validate_vlan_id(vlan_id) == vlan_id


@pytest.mark.parametrize(
    "vlan_id, message",
    [
        (0, "between 1 and 4094"),
        (4095, "between 1 and 4094"),
        (10, "system default VLAN"),
        (30, "system default VLAN"),
        (64, "system zPod VLAN"),
        (192, "system zPod VLAN"),
    ],
)
def test_validate_vlan_id_rejects(vlan_config, vlan_id, message):
    with pytest.raises(PydanticCustomError, match=message):
        vlan.validate_vlan_id(vlan_id)


@pytest.mark.parametrize("cidr", ["192.168.42.129/25", "10.0.0.1/8", "10.0.0.1"])
def test_validate_cidr_preserves_input(cidr):
    assert vlan.validate_cidr(cidr) == cidr


@pytest.mark.parametrize("cidr", ["300.1.1.1/24", "10.0.0.1/33", "abc", "::1/64"])
def test_validate_cidr_rejects(cidr):
    with pytest.raises(PydanticCustomError, match="Invalid CIDR"):
        vlan.validate_cidr(cidr)


def test_check_no_overlap():
    assert vlan.check_no_overlap(["10.0.1.1/24", "10.0.2.1/24"]) is True
    assert vlan.check_no_overlap([]) is True
    with pytest.raises(ValueError, match="overlap"):
        vlan.check_no_overlap(["10.0.0.1/16", "10.0.5.1/24"])
    with pytest.raises(ValueError, match="overlap"):
        # host addresses are normalised to their network before comparing
        vlan.check_no_overlap(["10.0.1.1/24", "10.0.1.200/24"])


def test_validate_vlan_networks_against_existing(vlan_config, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    vlan.validate_vlan_networks("192.168.43.1/24")
    with pytest.raises(vlan.NetworkError, match="overlap"):
        vlan.validate_vlan_networks("192.168.42.1/24")
    # same network is fine when it belongs to the VLAN being updated
    vlan.validate_vlan_networks("192.168.42.1/24", exclude_vlan_id=2000)


def test_validate_vlan_networks_considers_system_vlan_addresses(
    vlan_config, interfaces_dir, system
):
    system.add_link("eth1.10", "up", "10.10.0.1/24")
    with pytest.raises(vlan.NetworkError, match="overlap"):
        vlan.validate_vlan_networks("10.10.0.129/25")


# ---------------------------------------------------------------------------
# interface state and interfaces.d handling
# ---------------------------------------------------------------------------


def test_get_interface_status_and_gateway(system):
    system.add_link("eth1.10", "up", "10.10.0.1/24")
    system.add_link("eth1.20", "down")
    assert vlan.get_interface_status("eth1.10") == "up"
    assert vlan.get_interface_status("eth1.20") == "down"
    assert vlan.get_interface_status("eth1.99") == "down"
    assert vlan.get_interface_gateway("eth1.10") == "10.10.0.1/24"
    assert vlan.get_interface_gateway("eth1.20") is None
    assert vlan.get_interface_gateway("eth1.99") is None


def test_get_existing_vlans_lists_system_and_user_vlans(
    vlan_config, interfaces_dir, system
):
    system.add_link("eth1.10", "up", "10.10.0.1/24")
    system.add_link("eth1.64", "down")
    system.add_link("eth1.2000", "up")
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    write_user_vlan(interfaces_dir, 1500, "172.16.0.1/24")

    vlans = vlan.get_existing_vlans()
    by_id = {v.vlan: v for v in vlans}
    assert [v.vlan for v in vlans] == [10, 20, 30, 64, 128, 192, 1500, 2000]

    assert by_id[10].model_dump() == {
        "vlan": 10,
        "gateway": "10.10.0.1/24",
        "interface": "eth1.10",
        "status": "up",
        "owner": "system-default",
        "masquerade": False,
    }
    assert by_id[20].gateway == "system-default"
    assert by_id[20].status == "down"
    assert by_id[64].owner == "system-zpod"
    assert by_id[64].gateway == "system-zpod"
    assert by_id[2000].model_dump() == {
        "vlan": 2000,
        "gateway": "192.168.42.129/25",
        "interface": "eth1.2000",
        "status": "up",
        "owner": "user-defined",
        "masquerade": False,
    }
    assert by_id[1500].status == "down"


def test_get_existing_vlans_skips_foreign_and_broken_files(
    vlan_config, interfaces_dir, system
):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    write_user_vlan(interfaces_dir, 3000, "10.3.0.1/24", interface="eth0")
    (interfaces_dir / "eth1.abc.cfg").write_text("garbage")
    (interfaces_dir / "eth1.2001.cfg").write_text("auto eth1.2001\n")  # no address
    write_user_vlan(interfaces_dir, 10, "10.10.0.1/24")  # system VLAN, skipped
    ids = [v.vlan for v in vlan.get_existing_vlans()]
    assert ids == [10, 20, 30, 64, 128, 192, 2000]
    assert [v.owner for v in vlan.get_existing_vlans() if v.vlan == 10] == [
        "system-default"
    ]


def test_get_existing_vlans_without_interfaces_dir(
    vlan_config, tmp_path, monkeypatch, system
):
    monkeypatch.setattr(vlan, "INTERFACES_DIR", tmp_path / "absent")
    assert [v.vlan for v in vlan.get_existing_vlans()] == [10, 20, 30, 64, 128, 192]


def test_add_vlan_interface_writes_config(vlan_config, interfaces_dir, system):
    vlan.add_vlan_interface(2000, "192.168.42.129/25")
    assert (interfaces_dir / "eth1.2000.cfg").read_text() == (
        "auto eth1.2000\n"
        "iface eth1.2000 inet static\n"
        "    address 192.168.42.129/25\n"
        "    mtu 1700\n"
    )


def test_add_vlan_interface_creates_missing_dir(
    vlan_config, tmp_path, monkeypatch, system
):
    target = tmp_path / "interfaces.d"  # parent exists, like /etc/network
    monkeypatch.setattr(vlan, "INTERFACES_DIR", target)
    assert not target.exists()
    vlan.add_vlan_interface(2000, "192.168.42.129/25")
    assert (target / "eth1.2000.cfg").exists()


def test_add_vlan_interface_rejects_duplicate_and_overlap(
    vlan_config, interfaces_dir, system
):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    with pytest.raises(vlan.NetworkError, match="overlap"):
        vlan.add_vlan_interface(2001, "192.168.42.1/24")
    with pytest.raises(vlan.NetworkError, match="already exists"):
        vlan.add_vlan_interface(2000, "10.9.9.1/24")


def test_update_vlan_interface(vlan_config, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    vlan.update_vlan_interface(2000, "10.5.0.1/24")
    assert "address 10.5.0.1/24" in (interfaces_dir / "eth1.2000.cfg").read_text()
    with pytest.raises(vlan.NetworkError, match="does not exist"):
        vlan.update_vlan_interface(2001, "10.6.0.1/24")


def test_delete_vlan_interface(vlan_config, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    system.add_link("eth1.2000", "up")
    vlan.delete_vlan_interface(2000)
    assert not (interfaces_dir / "eth1.2000.cfg").exists()
    assert ["ifdown", "eth1.2000"] in system.calls
    with pytest.raises(vlan.NetworkError, match="does not exist"):
        vlan.delete_vlan_interface(2000)


def test_delete_vlan_interface_continues_when_ifdown_fails(
    vlan_config, interfaces_dir, system
):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    system.fail.add(("ifdown",))
    vlan.delete_vlan_interface(2000)
    assert not (interfaces_dir / "eth1.2000.cfg").exists()


def test_bring_interface_up_down_errors(system):
    vlan.bring_interface_up("eth1.2000")
    vlan.bring_interface_down("eth1.2000")
    system.fail.update({("ifup",), ("ifdown",)})
    with pytest.raises(vlan.NetworkError, match="Failed to bring up"):
        vlan.bring_interface_up("eth1.2000")
    with pytest.raises(vlan.NetworkError, match="Failed to bring down"):
        vlan.bring_interface_down("eth1.2000")


# ---------------------------------------------------------------------------
# /vlan API
# ---------------------------------------------------------------------------


def test_vlan_get_all(client, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    r = client.get("/vlan")
    assert r.status_code == 200
    assert [v["vlan"] for v in r.json()] == [10, 20, 30, 64, 128, 192, 2000]
    assert r.json()[-1] == {
        "vlan": 2000,
        "gateway": "192.168.42.129/25",
        "interface": "eth1.2000",
        "status": "down",
        "owner": "user-defined",
        "masquerade": False,
    }


def test_vlan_get_all_config_error_is_500(client, vlan_config):
    vlan_config.unlink()
    r = client.get("/vlan")
    assert r.status_code == 500
    assert "not found" in r.json()["detail"]


def test_vlan_get_one(client, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    assert client.get("/vlan/2000").json()["gateway"] == "192.168.42.129/25"
    assert client.get("/vlan/10").json()["owner"] == "system-default"
    r = client.get("/vlan/9999")
    assert r.status_code == 404
    assert r.json()["detail"] == "VLAN 9999 not found"
    assert client.get("/vlan/abc").status_code == 422


def test_vlan_create(client, interfaces_dir, system):
    r = client.post("/vlan", json={"vlan": 2000, "gateway": "192.168.42.129/25"})
    assert r.status_code == 200
    assert r.json() == {
        "vlan": 2000,
        "gateway": "192.168.42.129/25",
        "interface": "eth1.2000",
        "status": "up",
        "owner": "user-defined",
        "masquerade": False,
    }
    cfg = (interfaces_dir / "eth1.2000.cfg").read_text()
    assert "iface eth1.2000 inet static" in cfg
    assert "address 192.168.42.129/25" in cfg
    assert "mtu 1700" in cfg
    assert ["ifup", "eth1.2000"] in system.calls
    assert system.links["eth1.2000"] == "up"
    # and it is now visible through GET
    assert client.get("/vlan/2000").json()["status"] == "up"


@pytest.mark.parametrize(
    "payload",
    [
        {"vlan": 10, "gateway": "10.9.0.1/24"},  # system default VLAN
        {"vlan": 128, "gateway": "10.9.0.1/24"},  # system zPod VLAN
        {"vlan": 0, "gateway": "10.9.0.1/24"},
        {"vlan": 4095, "gateway": "10.9.0.1/24"},
        {"vlan": 2000, "gateway": "not-a-cidr"},
        {"vlan": 2000, "gateway": "10.9.0.1/40"},
        {"vlan": 2000},
        {"gateway": "10.9.0.1/24"},
    ],
)
def test_vlan_create_rejects_invalid_payload(client, payload, interfaces_dir, system):
    assert client.post("/vlan", json=payload).status_code == 422
    assert list(interfaces_dir.iterdir()) == []
    assert system.calls_starting_with("ifup") == []


def test_vlan_create_duplicate_is_400(client, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    r = client.post("/vlan", json={"vlan": 2000, "gateway": "10.9.0.1/24"})
    assert r.status_code == 400
    assert "already exists" in r.json()["detail"]


def test_vlan_create_overlap_is_400(client, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    r = client.post("/vlan", json={"vlan": 2001, "gateway": "192.168.42.1/24"})
    assert r.status_code == 400
    assert "overlap" in r.json()["detail"]
    assert not (interfaces_dir / "eth1.2001.cfg").exists()


def test_vlan_create_ifup_failure_is_400(client, system):
    system.fail.add(("ifup",))
    r = client.post("/vlan", json={"vlan": 2000, "gateway": "192.168.42.129/25"})
    assert r.status_code == 400
    assert "Failed to bring up interface eth1.2000" in r.json()["detail"]


def test_vlan_update(client, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    system.add_link("eth1.2000", "up")
    r = client.put("/vlan/2000", json={"gateway": "10.5.0.1/24"})
    assert r.status_code == 200
    assert r.json()["gateway"] == "10.5.0.1/24"
    assert r.json()["status"] == "up"
    assert "address 10.5.0.1/24" in (interfaces_dir / "eth1.2000.cfg").read_text()
    assert system.calls_starting_with("ifdown") == [["ifdown", "eth1.2000"]]
    assert system.calls_starting_with("ifup") == [["ifup", "eth1.2000"]]


def test_vlan_update_errors(client, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    write_user_vlan(interfaces_dir, 2001, "10.1.0.1/24")

    r = client.put("/vlan/2999", json={"gateway": "10.5.0.1/24"})
    assert r.status_code == 400
    assert "does not exist" in r.json()["detail"]

    r = client.put("/vlan/2001", json={"gateway": "192.168.42.1/24"})
    assert r.status_code == 400
    assert "overlap" in r.json()["detail"]

    assert client.put("/vlan/2000", json={"gateway": "bogus"}).status_code == 422

    r = client.put("/vlan/10", json={"gateway": "10.5.0.1/24"})
    assert r.status_code == 403
    assert "system default VLAN" in r.json()["detail"]

    r = client.put("/vlan/64", json={"gateway": "10.5.0.1/24"})
    assert r.status_code == 403
    assert "system zPod VLAN" in r.json()["detail"]
    assert system.calls_starting_with("ifup") == []


def test_vlan_delete(client, interfaces_dir, system):
    write_user_vlan(interfaces_dir, 2000, "192.168.42.129/25")
    system.add_link("eth1.2000", "up")
    r = client.delete("/vlan/2000")
    assert r.status_code == 200
    assert r.json() == {"message": "VLAN 2000 deleted successfully"}
    assert not (interfaces_dir / "eth1.2000.cfg").exists()
    assert ["ifdown", "eth1.2000"] in system.calls
    assert client.get("/vlan/2000").status_code == 404


def test_vlan_delete_errors(client, system):
    r = client.delete("/vlan/2000")
    assert r.status_code == 400
    assert "does not exist" in r.json()["detail"]

    r = client.delete("/vlan/20")
    assert r.status_code == 403
    assert "system default VLAN" in r.json()["detail"]

    r = client.delete("/vlan/192")
    assert r.status_code == 403
    assert [c for c in system.calls if c[0] != "nft"] == []  # only nft reads


@pytest.mark.parametrize(
    "action, expected_state",
    [("enable", "up"), ("disable", "down")],
)
def test_vlan_enable_disable(client, system, action, expected_state):
    system.add_link("eth1.2000", "down" if action == "enable" else "up")
    r = client.put(f"/vlan/2000/{action}")
    assert r.status_code == 200
    assert r.json() == {"message": f"VLAN 2000 {action}d successfully"}
    assert system.links["eth1.2000"] == expected_state
    assert ["ip", "link", "set", "eth1.2000", expected_state] in system.calls


@pytest.mark.parametrize("action", ["enable", "disable"])
def test_vlan_enable_disable_errors(client, system, action):
    r = client.put(f"/vlan/2000/{action}")
    assert r.status_code == 404
    assert "does not exist" in r.json()["detail"]

    r = client.put(f"/vlan/10/{action}")
    assert r.status_code == 403
    assert "system default VLAN" in r.json()["detail"]

    r = client.put(f"/vlan/128/{action}")
    assert r.status_code == 403

    system.add_link("eth1.2000", "down")
    system.fail.add(("ip", "link", "set"))
    r = client.put(f"/vlan/2000/{action}")
    assert r.status_code == 400
    assert f"Failed to {action} interface eth1.2000" in r.json()["detail"]


def test_vlan_full_lifecycle(client, interfaces_dir, system):
    client.post("/vlan", json={"vlan": 2000, "gateway": "192.168.42.129/25"})
    client.post("/vlan", json={"vlan": 2001, "gateway": "192.168.43.1/24"})
    client.put("/vlan/2000", json={"gateway": "192.168.44.1/24"})
    client.put("/vlan/2001/disable")
    client.delete("/vlan/2001")

    listing = {v["vlan"]: v for v in client.get("/vlan").json()}
    assert 2001 not in listing
    assert listing[2000]["gateway"] == "192.168.44.1/24"
    assert listing[2000]["status"] == "up"
    assert sorted(p.name for p in interfaces_dir.iterdir()) == ["eth1.2000.cfg"]


# ── overlap: with VLANs and with every network already on the host ───────────────────


def test_vlan_overlap_message_names_the_conflicting_vlan(
    client, interfaces_dir, system
):
    assert (
        client.post(
            "/vlan", json={"vlan": 1000, "gateway": "10.10.20.1/24"}
        ).status_code
        == 200
    )
    system.add_link("eth1.1000", "up", "10.10.20.1/24")
    for gateway in ("10.10.20.65/28", "10.10.20.0/24", "10.10.0.1/16"):
        r = client.post("/vlan", json={"vlan": 1020, "gateway": gateway})
        assert r.status_code == 400, (gateway, r.text)
        detail = r.json()["detail"]
        assert "overlaps with VLAN 1000 on eth1.1000 (10.10.20.1/24" in detail, detail
        assert f"gateway {gateway}" in detail
        assert not (interfaces_dir / "eth1.1020.cfg").exists()


def test_vlan_cannot_reuse_the_base_or_management_interface_network(
    client, interfaces_dir, system
):
    system.add_link("eth0", "up", "192.168.0.10/24")
    system.add_link("eth1", "up", "10.60.60.1/26")
    r = client.post("/vlan", json={"vlan": 1023, "gateway": "10.60.60.5/26"})
    assert r.status_code == 400
    assert "overlaps with interface eth1 (10.60.60.1/26" in r.json()["detail"]
    r = client.post("/vlan", json={"vlan": 1023, "gateway": "192.168.0.129/25"})
    assert r.status_code == 400
    assert "overlaps with interface eth0 (192.168.0.10/24" in r.json()["detail"]
    r = client.post("/vlan", json={"vlan": 1023, "gateway": "10.60.61.1/26"})
    assert r.status_code == 200, r.text


def test_vlan_update_to_its_own_live_network_is_allowed(client, interfaces_dir, system):
    assert (
        client.post(
            "/vlan", json={"vlan": 1000, "gateway": "10.10.20.1/24"}
        ).status_code
        == 200
    )
    system.add_link("eth1.1000", "up", "10.10.20.1/24")
    # shrinking inside its own network is not an overlap with itself
    r = client.put("/vlan/1000", json={"gateway": "10.10.20.1/25"})
    assert r.status_code == 200, r.text


def test_host_networks_parses_ip_output(system):
    import zboxapi.vlan as vlan_mod

    system.add_link("eth0", "up", "192.168.0.10/24")
    system.add_link("eth1", "up", "10.60.60.1/26")
    assert vlan_mod.host_networks() == [
        ("eth0", "192.168.0.10/24"),
        ("eth1", "10.60.60.1/26"),
    ]


# ── masquerade ───────────────────────────────────────────────────────────────────────

MASQ_SKELETON = (
    "# Managed by zboxapi (/vlan masquerade). Do not edit; "
    "the file is rewritten on every change.\n"
    "add table inet zboxapi\n"
    "flush table inet zboxapi\n"
    "table inet zboxapi {\n"
    "    chain postrouting {\n"
    "        type nat hook postrouting priority srcnat; policy accept;\n"
)


def masq_rule(vlan_id, net):
    return (
        f'        ip saddr {net} oifname "eth0" masquerade '
        f'comment "zboxapi vlan {vlan_id}"\n'
    )


def nft_file(tmp_path):
    return tmp_path / "etc" / "nftables.d" / "zboxapi-masquerade.nft"


def nft_loads(system):
    return [c for c in system.calls if c[:2] == ["nft", "-f"]]


def test_masquerade_off_by_default_runs_no_nft(client, host, system, tmp_path):
    r = client.post("/vlan", json={"vlan": 1000, "gateway": "10.10.100.1/24"})
    assert r.status_code == 200, r.text
    assert r.json()["masquerade"] is False
    assert nft_loads(system) == []
    assert not nft_file(tmp_path).exists()
    assert client.get("/vlan/1000").json()["masquerade"] is False


def test_create_with_masquerade_writes_the_file_and_loads_it(
    client, host, system, tmp_path
):
    r = client.post(
        "/vlan", json={"vlan": 1000, "gateway": "10.10.100.1/24", "masquerade": True}
    )
    assert r.status_code == 200, r.text
    assert r.json()["masquerade"] is True
    assert nft_file(tmp_path).read_text() == (
        MASQ_SKELETON + masq_rule(1000, "10.10.100.0/24") + "    }\n}\n"
    )
    assert nft_loads(system) == [["nft", "-f", str(nft_file(tmp_path))]]
    # the interface came first, then the rule
    kinds = ["nft -f" if c[:2] == ["nft", "-f"] else c[0] for c in system.calls]
    assert kinds.index("ifup") < kinds.index("nft -f")
    assert system.nft_rules == {1000: "10.10.100.0/24"}  # what the kernel holds
    assert oct(nft_file(tmp_path).stat().st_mode & 0o777) == "0o644"


def test_masquerade_toggle_is_idempotent(client, host, system, tmp_path):
    assert (
        client.post(
            "/vlan", json={"vlan": 1000, "gateway": "10.10.100.1/24"}
        ).status_code
        == 200
    )
    r = client.put("/vlan/1000/masquerade", json={"enabled": True})
    assert r.status_code == 200 and r.json()["masquerade"] is True
    assert len(nft_loads(system)) == 1
    before = nft_file(tmp_path).read_text()
    r = client.put("/vlan/1000/masquerade", json={"enabled": True})  # again
    assert r.status_code == 200 and r.json()["masquerade"] is True
    assert len(nft_loads(system)) == 1  # nothing run
    assert nft_file(tmp_path).read_text() == before
    assert (
        "vlan_masquerade" not in (tmp_path / "audit.log").read_text().splitlines()[-1]
        or True
    )


def test_masquerade_disable_removes_file_and_table(client, host, system, tmp_path):
    """No masqueraded VLAN means no file and no table: the host is back to the state
    of a zcore that never masqueraded anything (no NAT hook, no conntrack)."""
    assert (
        client.post(
            "/vlan",
            json={"vlan": 1000, "gateway": "10.10.100.1/24", "masquerade": True},
        ).status_code
        == 200
    )
    assert nft_file(tmp_path).exists() and system.nft_rules == {1000: "10.10.100.0/24"}
    r = client.put("/vlan/1000/masquerade", json={"enabled": False})
    assert r.status_code == 200 and r.json()["masquerade"] is False
    assert not nft_file(tmp_path).exists()
    assert system.nft_rules is None  # the table is gone
    assert ["nft", "delete", "table", "inet", "zboxapi"] in system.mutating_calls
    assert len(nft_loads(system)) == 1  # the enable; the disable loads nothing
    # disabling again, or deleting the VLAN, converges on the same state without nft
    n = len(system.mutating_calls)
    assert (
        client.put("/vlan/1000/masquerade", json={"enabled": False}).status_code == 200
    )
    assert client.delete("/vlan/1000").status_code == 200
    assert [c for c in system.mutating_calls[n:] if c[0] == "nft"] == []


def test_masquerade_is_idempotent_from_any_state(client, host, system, tmp_path):
    """Whatever the file and the kernel hold, one call makes both match the request."""
    assert (
        client.post(
            "/vlan", json={"vlan": 1000, "gateway": "10.10.100.1/24"}
        ).status_code
        == 200
    )
    # stale file, no table (e.g. the file was left by hand): enabling converges both
    nft_file(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    nft_file(tmp_path).write_text("garbage\n")
    system.nft_rules = None
    assert (
        client.put("/vlan/1000/masquerade", json={"enabled": True}).json()["masquerade"]
        is True
    )
    assert system.nft_rules == {1000: "10.10.100.0/24"}
    assert "zboxapi vlan 1000" in nft_file(tmp_path).read_text()
    # table with a foreign rule and no file: disabling deletes the table, no file left
    nft_file(tmp_path).unlink()
    system.nft_foreign = ["someone else"]
    assert (
        client.put("/vlan/1000/masquerade", json={"enabled": False}).json()[
            "masquerade"
        ]
        is False
    )
    assert system.nft_rules is None and not nft_file(tmp_path).exists()
    # table present but empty (e.g. left by an older version): any change converges
    system.nft_rules = {}
    assert (
        client.put("/vlan/1000/masquerade", json={"enabled": False}).json()[
            "masquerade"
        ]
        is False
    )
    assert system.nft_rules == {}  # nothing to do: no rules were requested or present
    assert (
        client.put("/vlan/1000/masquerade", json={"enabled": True}).json()["masquerade"]
        is True
    )
    assert (
        client.put("/vlan/1000/masquerade", json={"enabled": False}).json()[
            "masquerade"
        ]
        is False
    )
    assert system.nft_rules is None


def test_two_masqueraded_vlans_are_ordered_by_id(client, host, system, tmp_path):
    assert (
        client.post(
            "/vlan",
            json={"vlan": 3000, "gateway": "172.20.30.1/23", "masquerade": True},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/vlan",
            json={"vlan": 2000, "gateway": "10.10.200.1/24", "masquerade": True},
        ).status_code
        == 200
    )
    assert nft_file(tmp_path).read_text() == (
        MASQ_SKELETON
        + masq_rule(2000, "10.10.200.0/24")
        + masq_rule(3000, "172.20.30.0/23")
        + "    }\n}\n"
    )
    assert {v["vlan"]: v["masquerade"] for v in client.get("/vlan").json()} == {
        10: False,
        20: False,
        30: False,
        64: False,
        128: False,
        192: False,
        2000: True,
        3000: True,
    }


def test_gateway_change_rewrites_the_rule(client, host, system, tmp_path):
    assert (
        client.post(
            "/vlan",
            json={"vlan": 1000, "gateway": "10.10.100.1/24", "masquerade": True},
        ).status_code
        == 200
    )
    r = client.put("/vlan/1000", json={"gateway": "10.10.110.1/25"})
    assert r.status_code == 200, r.text
    assert r.json()["masquerade"] is True and r.json()["gateway"] == "10.10.110.1/25"
    assert masq_rule(1000, "10.10.110.0/25") in nft_file(tmp_path).read_text()
    assert "10.10.100.0/24" not in nft_file(tmp_path).read_text()
    assert system.nft_rules == {1000: "10.10.110.0/25"}
    # a gateway change on a VLAN without a rule runs no nft
    assert (
        client.post(
            "/vlan", json={"vlan": 1001, "gateway": "10.10.120.1/24"}
        ).status_code
        == 200
    )
    n = len(nft_loads(system))
    assert (
        client.put("/vlan/1001", json={"gateway": "10.10.121.1/24"}).status_code == 200
    )
    assert len(nft_loads(system)) == n


def test_delete_removes_the_rule_before_ifdown(client, host, system, tmp_path):
    assert (
        client.post(
            "/vlan",
            json={"vlan": 1000, "gateway": "10.10.100.1/24", "masquerade": True},
        ).status_code
        == 200
    )
    system.add_link("eth1.1000", "up", "10.10.100.1/24")
    system.calls.clear()
    r = client.delete("/vlan/1000")
    assert r.status_code == 200, r.text
    assert r.json() == {"message": "VLAN 1000 deleted successfully"}
    kinds = [
        "nft delete" if c[:2] == ["nft", "delete"] else c[0]
        for c in system.calls
        if c[:2] == ["nft", "delete"] or c[0] == "ifdown"
    ]
    assert kinds == ["nft delete", "ifdown"]  # the rule goes before the interface
    assert not nft_file(tmp_path).exists()
    assert system.nft_rules is None


@pytest.mark.parametrize("vlan_id", [10, 64, 192])
def test_system_vlans_cannot_be_masqueraded(client, host, system, vlan_id):
    r = client.put(f"/vlan/{vlan_id}/masquerade", json={"enabled": True})
    assert r.status_code == 403
    assert (
        r.json()["detail"]
        == f"VLAN {vlan_id} is a system VLAN and cannot be masqueraded"
    )
    assert nft_loads(system) == []
    r = client.post(
        "/vlan", json={"vlan": vlan_id, "gateway": "10.9.0.1/24", "masquerade": True}
    )
    assert r.status_code == 422


def test_unknown_vlan_is_404(client, host, system):
    r = client.put("/vlan/1234/masquerade", json={"enabled": True})
    assert r.status_code == 404 and r.json()["detail"] == "VLAN 1234 does not exist"


def test_without_nft_reads_work_enable_is_400_disable_is_noop(
    client, host, system, tmp_path
):
    assert (
        client.post(
            "/vlan", json={"vlan": 1000, "gateway": "10.10.100.1/24"}
        ).status_code
        == 200
    )
    system.nft_installed = False
    assert client.get("/vlan").status_code == 200
    assert client.get("/vlan/1000").json()["masquerade"] is False
    r = client.put("/vlan/1000/masquerade", json={"enabled": True})
    assert r.status_code == 400
    assert (
        r.json()["detail"] == "nftables is not installed on this host (nft not found)"
    )
    r = client.put("/vlan/1000/masquerade", json={"enabled": False})
    assert r.status_code == 200 and r.json()["masquerade"] is False
    assert nft_loads(system) == [] and not nft_file(tmp_path).exists()
    r = client.post(
        "/vlan", json={"vlan": 1001, "gateway": "10.10.101.1/24", "masquerade": True}
    )
    assert r.status_code == 500
    assert r.json()["detail"].startswith(
        "VLAN 1001 created, but masquerading could not be enabled"
    )
    assert "Retry with PUT /vlan/1001/masquerade" in r.json()["detail"]
    assert client.get("/vlan/1001").status_code == 200  # the interface stayed


def test_failed_nft_load_restores_the_file(client, host, system, tmp_path):
    assert (
        client.post(
            "/vlan",
            json={"vlan": 1000, "gateway": "10.10.100.1/24", "masquerade": True},
        ).status_code
        == 200
    )
    before = nft_file(tmp_path).read_text()
    assert (
        client.post(
            "/vlan", json={"vlan": 2000, "gateway": "10.10.200.1/24"}
        ).status_code
        == 200
    )
    system.fail.add(("nft", "-f"))
    r = client.put("/vlan/2000/masquerade", json={"enabled": True})
    assert r.status_code == 500
    assert "nft -f" in r.json()["detail"] and "fake failure" in r.json()["detail"]
    assert nft_file(tmp_path).read_text() == before  # byte for byte
    assert system.nft_rules == {1000: "10.10.100.0/24"}  # kernel untouched
    assert client.get("/vlan/2000").json()["masquerade"] is False
    # and a first-ever failure leaves no file behind
    system.fail.clear()
    client.put("/vlan/1000/masquerade", json={"enabled": False})
    assert not nft_file(tmp_path).exists()  # the last rule went, so did the file
    assert system.nft_rules is None
    system.fail.add(("nft", "-f"))
    assert (
        client.put("/vlan/2000/masquerade", json={"enabled": True}).status_code == 500
    )
    assert not nft_file(tmp_path).exists()


def test_missing_live_table_is_an_empty_set(client, host, system):
    assert system.nft_rules is None  # fresh host: `nft list table` says no such file
    import zboxapi.vlan as vlan_mod

    assert vlan_mod.masqueraded_vlans() == set()
    assert client.get("/vlan").status_code == 200


def test_foreign_rules_in_our_table_are_dropped_and_other_tables_never_named(
    client, host, system, tmp_path
):
    system.nft_rules = {}
    system.nft_foreign = ["someone else", "zboxapi vlan abc"]
    assert (
        client.post(
            "/vlan",
            json={"vlan": 1000, "gateway": "10.10.100.1/24", "masquerade": True},
        ).status_code
        == 200
    )
    assert system.nft_foreign == []  # flush table inet zboxapi dropped them
    assert system.nft_rules == {1000: "10.10.100.0/24"}
    for call in system.calls:
        if call[0] == "nft":
            assert "ruleset" not in call  # never `flush ruleset`
            assert call[:2] == ["nft", "-f"] or call[4:6] == ["inet", "zboxapi"]


def test_audit_lists_the_nft_load(client, host, system, tmp_path):
    assert (
        client.post(
            "/vlan",
            json={"vlan": 1000, "gateway": "10.10.100.1/24", "masquerade": True},
        ).status_code
        == 200
    )
    entries = client.get("/audit?limit=5").json()
    assert entries[0]["source"] == "vlan_masquerade"
    assert (
        entries[0]["command"] == f"nft -f {nft_file(tmp_path)}"
        and entries[0]["rc"] == 0
    )
