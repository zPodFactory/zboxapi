import contextlib
import fcntl
import os
import re
import socket
import subprocess
import time
from ipaddress import IPv4Address
from pathlib import Path
from typing import IO, Annotated

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Security, status
from fastapi.routing import APIRoute
from fastapi.security.api_key import APIKey, APIKeyHeader
from pydantic import AfterValidator, BaseModel
from pydantic_core import PydanticCustomError

from zboxapi import __version__

api_key_header = APIKeyHeader(name="access_token", auto_error=False)


@contextlib.contextmanager
def get_hosts_file_object():
    pfile = Path("/etc/hosts")
    if not pfile.is_file():
        pfile.write_text("")

    while True:
        try:
            file_handle = pfile.open("r+")
            fcntl.flock(file_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except IOError:  # noqa: UP024
            # File is locked, wait for a while and try again
            time.sleep(0.1)

    try:
        yield file_handle
    finally:
        fcntl.flock(file_handle, fcntl.LOCK_UN)
        file_handle.close()


def get_hosts_lines(hosts_fo: IO) -> list[dict[str, str]]:
    lines = []
    for line in hosts_fo.read().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line_ip, *line_fqdns = line.split()
        lines.extend(
            {"ip": IPv4Address(line_ip), "fqdn": line_fqdn} for line_fqdn in line_fqdns
        )
    return sorted(lines, key=sort_hosts_lines)


def filter_hosts_file(
    lines: list[dict[str, str]],
    ip: IPv4Address | None = None,
    fqdn: str | None = None,
):
    return [
        line
        for line in lines
        if (not ip or ip == line["ip"]) and (not fqdn or fqdn == line["fqdn"])
    ]


def write_hosts_file(hosts_fo: IO, lines: list[dict[str, str]]):
    lines.sort(key=sort_hosts_lines)
    hosts_fo.seek(0)
    hosts_fo.truncate()
    hosts_fo.writelines([f"{line['ip']}\t{line['fqdn']}\n" for line in lines])


def validate_api_key(api_key: Annotated[APIKey, Security(api_key_header)]):
    if api_key != ZPOD_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid access_token",
        )


def get_zpod_password():
    ovfenv = subprocess.run(
        ["vmtoolsd", "--cmd", "info-get guestinfo.ovfenv"],
        capture_output=True,
        text=True,
    )
    pw_re = re.compile(r'<Property oe:key="guestinfo.password" oe:value="([^"]*)"/>')
    if item := re.search(pw_re, ovfenv.stdout):
        return item[1]
    raise Exception("Unable to retrieve zpod password")


def dnsmasq_sighup():
    print("Send SIGHUP to dnsmasq...")
    subprocess.call(["pkill", "-SIGHUP", "dnsmasq"])


def sort_hosts_lines(item: dict):
    """Sort list by loopback first, ip second, fqdn third"""
    return (
        not item["ip"].is_loopback,
        socket.inet_aton(str(item["ip"])),
        item["fqdn"],
    )


def simplify_operation_ids(api: FastAPI) -> None:
    """
    Update operation IDs so that generated API clients have simpler function
    names.
    """
    for route in api.routes:
        if isinstance(route, APIRoute) and not route.operation_id:
            tag = route.tags[0] if route.tags else "default"
            route.operation_id = f"{tag}_{route.name}"


def RecordNotFound(ip, fqdn):
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"DNS record not found: ip={ip}, fqdn={fqdn}",
    )


def RecordAlreadyPresent(ip, fqdn):
    return HTTPException(
        status_code=status.HTTP_406_NOT_ACCEPTABLE,
        detail=f"DNS record already present: ip={ip}, fqdn={fqdn}",
    )


def validate_fqdn(value: str):
    """
    https://en.m.wikipedia.org/wiki/Fully_qualified_domain_name
    """

    if not 1 < len(value) < 253:
        raise PydanticCustomError("value_error", "Invalid fqdn length")

    # Remove trailing dot
    if value[-1] == ".":
        value = value[:-1]

    #  Split hostname into list of DNS labels
    labels = value.split(".")

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r"^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

    # Check that all labels match that pattern.
    if not all(fqdn.match(label) for label in labels):
        raise PydanticCustomError("value_error", "Invalid fqdn")
    return value


FQDN = Annotated[str, AfterValidator(validate_fqdn)]


class DnsCreate(BaseModel):
    ip: IPv4Address
    fqdn: FQDN


class DnsDelete(BaseModel):
    ip: IPv4Address
    fqdn: FQDN


class DnsUpdate(BaseModel):
    ip: IPv4Address
    fqdn: FQDN


class DnsView(BaseModel):
    ip: IPv4Address
    fqdn: str


dns_router = APIRouter(prefix="/dns", tags=["dns"])


@dns_router.get("")
def dns_get_all() -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
    return hosts_lines


@dns_router.get("/{ip}/{fqdn}")
def dns_get(
    ip: IPv4Address,
    fqdn: FQDN,
) -> DnsView:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        hosts_lines = filter_hosts_file(hosts_lines, ip, fqdn)
    if not hosts_lines:
        raise RecordNotFound(ip, fqdn)
    return hosts_lines[0]


@dns_router.post("")
def dns_add(
    dns_in: DnsCreate,
) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        if filter_hosts_file(hosts_lines, dns_in.ip, dns_in.fqdn):
            raise RecordAlreadyPresent(dns_in.ip, dns_in.fqdn)
        hosts_lines.append({"ip": dns_in.ip, "fqdn": dns_in.fqdn})
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


@dns_router.put("/{ip}/{fqdn}")
def dns_update(
    ip: IPv4Address,
    fqdn: FQDN,
    dns_in: DnsUpdate,
) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        key = {"ip": ip, "fqdn": fqdn}
        if key not in hosts_lines:
            raise RecordNotFound(ip, fqdn)
        ix = hosts_lines.index(key)
        hosts_lines[ix] = {"ip": dns_in.ip, "fqdn": dns_in.fqdn}
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


@dns_router.delete("/{ip}/{fqdn}")
def dns_delete(
    ip: IPv4Address,
    fqdn: FQDN,
) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        key = {"ip": ip, "fqdn": fqdn}
        if key not in hosts_lines:
            raise RecordNotFound(ip, fqdn)
        hosts_lines.remove(key)
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


zboxapi_root_path = os.getenv("ZBOXAPI_ROOT_PATH", None)

app = FastAPI(
    title="zBox API",
    root_path=zboxapi_root_path,
    dependencies=[Depends(validate_api_key)],
    version=__version__,
)
app.include_router(dns_router)
simplify_operation_ids(app)

ZPOD_PASSWORD = get_zpod_password()


def launch():
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
    )


if __name__ == "__main__":
    launch()
