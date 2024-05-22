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
        line_ip, *line_hostnames = line.split()
        lines.extend(
            {"ip": IPv4Address(line_ip), "hostname": line_hostname}
            for line_hostname in line_hostnames
        )
    return sorted(lines, key=sort_hosts_lines)


def filter_hosts_file(
    lines: list[dict[str, str]],
    ip: IPv4Address | None = None,
    hostname: str | None = None,
):
    return [
        line
        for line in lines
        if (not ip or ip == line["ip"])
        and (not hostname or hostname == line["hostname"])
    ]


def write_hosts_file(hosts_fo: IO, lines: list[dict[str, str]]):
    lines.sort(key=sort_hosts_lines)
    hosts_fo.seek(0)
    hosts_fo.truncate()
    hosts_fo.writelines([f"{line['ip']}\t{line['hostname']}\n" for line in lines])


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
    """Sort list by loopback first, ip second, hostname third"""
    return (
        not item["ip"].is_loopback,
        socket.inet_aton(str(item["ip"])),
        item["hostname"],
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


def RecordNotFound(ip, hostname):
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"DNS record not found: ip={ip}, hostname={hostname}",
    )


def RecordAlreadyPresent(ip, hostname):
    return HTTPException(
        status_code=status.HTTP_406_NOT_ACCEPTABLE,
        detail=f"DNS record already present: ip={ip}, hostname={hostname}",
    )


def validate_hostname(value: str):
    if not 1 < len(value) < 64:
        raise PydanticCustomError("value_error", "Invalid hostname length")

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    hostname_re = re.compile(r"^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

    # Check that all labels match that pattern.
    if not hostname_re.match(value):
        raise PydanticCustomError("value_error", "Invalid hostname")
    return value


HOSTNAME = Annotated[str, AfterValidator(validate_hostname)]


class DnsCreate(BaseModel):
    ip: IPv4Address
    hostname: HOSTNAME


class DnsDelete(BaseModel):
    ip: IPv4Address
    hostname: HOSTNAME


class DnsUpdate(BaseModel):
    ip: IPv4Address
    hostname: HOSTNAME


class DnsView(BaseModel):
    ip: IPv4Address
    hostname: str


dns_router = APIRouter(prefix="/dns", tags=["dns"])


@dns_router.get("")
def dns_get_all() -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
    return hosts_lines


@dns_router.get("/{ip}/{hostname}")
def dns_get(
    ip: IPv4Address,
    hostname: HOSTNAME,
) -> DnsView:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        hosts_lines = filter_hosts_file(hosts_lines, ip, hostname)
    if not hosts_lines:
        raise RecordNotFound(ip, hostname)
    return hosts_lines[0]


@dns_router.post("")
def dns_add(
    dns_in: DnsCreate,
) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        if filter_hosts_file(hosts_lines, dns_in.ip, dns_in.hostname):
            raise RecordAlreadyPresent(dns_in.ip, dns_in.hostname)
        hosts_lines.append({"ip": dns_in.ip, "hostname": dns_in.hostname})
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


@dns_router.put("/{ip}/{hostname}")
def dns_update(
    ip: IPv4Address,
    hostname: HOSTNAME,
    dns_in: DnsUpdate,
) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        key = {"ip": ip, "hostname": hostname}
        if key not in hosts_lines:
            raise RecordNotFound(ip, hostname)
        ix = hosts_lines.index(key)
        hosts_lines[ix] = {"ip": dns_in.ip, "hostname": dns_in.hostname}
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


@dns_router.delete("/{ip}/{hostname}")
def dns_delete(
    ip: IPv4Address,
    hostname: HOSTNAME,
) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        key = {"ip": ip, "hostname": hostname}
        if key not in hosts_lines:
            raise RecordNotFound(ip, hostname)
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
