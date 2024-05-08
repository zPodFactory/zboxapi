import contextlib
import fcntl
import re
import socket

# import ssl
import subprocess
import time
from ipaddress import IPv4Address
from pathlib import Path
from typing import IO, Annotated

import uvicorn
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Security, status
from fastapi.security.api_key import APIKey, APIKeyHeader
from pydantic import AfterValidator, BaseModel
from pydantic_core import PydanticCustomError

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


def make_list(obj):
    return obj if isinstance(obj, list) else [obj]


def ip_fqdn_str(obj, ip_key="ip", fqdn_key="fqdn"):
    return f"ip={getattr(obj, ip_key)}, fqdn={getattr(obj, fqdn_key)}"


def ip_fqdn_dict(obj, ip_key="ip", fqdn_key="fqdn"):
    return {"ip": getattr(obj, ip_key), "fqdn": getattr(obj, fqdn_key)}


def RecordNotFound(obj, ip_key="ip", fqdn_key="fqdn"):
    return HTTPException(
        status_code=status.HTTP_406_NOT_ACCEPTABLE,
        detail=f"Record not found: {ip_fqdn_str(obj, ip_key, fqdn_key)}",
    )


def RecordAlreadyPresent(obj, ip_key="ip", fqdn_key="fqdn"):
    return HTTPException(
        status_code=status.HTTP_406_NOT_ACCEPTABLE,
        detail=f"Record already present: {ip_fqdn_str(obj, ip_key, fqdn_key)}",
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
    new_ip: IPv4Address
    new_fqdn: FQDN


class DnsView(BaseModel):
    ip: IPv4Address
    fqdn: str


hosts_router = APIRouter(prefix="/hosts", tags=["hosts"])


@hosts_router.get("")
def get_hosts(
    ip: IPv4Address | None = None,
    fqdn: str | None = None,
) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        hosts_lines = filter_hosts_file(hosts_lines, ip, fqdn)
    return hosts_lines


@hosts_router.post("")
def add_hosts(lines_in: list[DnsCreate] | DnsCreate) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        for line in make_list(lines_in):
            if filter_hosts_file(hosts_lines, line.ip, line.fqdn):
                raise RecordAlreadyPresent(line)
            hosts_lines.append(ip_fqdn_dict(line))
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


@hosts_router.put("")
def update_hosts(lines_in: list[DnsUpdate] | DnsUpdate) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        for line in make_list(lines_in):
            key = ip_fqdn_dict(line)
            if key not in hosts_lines:
                raise RecordNotFound(line)
            ix = hosts_lines.index(key)
            hosts_lines[ix] = ip_fqdn_dict(line, "new_ip", "new_fqdn")
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


@hosts_router.delete("")
def delete_hosts(lines_in: list[DnsDelete] | DnsDelete) -> list[DnsView]:
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        for line in make_list(lines_in):
            key = ip_fqdn_dict(line)
            if key not in hosts_lines:
                raise RecordNotFound(line)
            hosts_lines.remove(key)
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


app = FastAPI(title="zPod zBox API", dependencies=[Depends(validate_api_key)])
app.include_router(hosts_router)
ZPOD_PASSWORD = get_zpod_password()


def launch():
    uvicorn.run(
        app,
        host="zbox",
        port=8000,
    )


if __name__ == "__main__":
    launch()
