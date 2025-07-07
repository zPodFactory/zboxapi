import contextlib
import fcntl
import re
import socket
import subprocess
import time
from ipaddress import IPv4Address
from pathlib import Path
from typing import IO, Annotated

from fastapi import APIRouter, HTTPException, status
from pydantic import AfterValidator, BaseModel
from pydantic_core import PydanticCustomError


@contextlib.contextmanager
def get_hosts_file_object():
    """Context manager for safely handling /etc/hosts file"""
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
    """Parse hosts file and return list of IP-hostname mappings"""
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
    """Filter hosts file lines by IP and/or hostname"""
    return [
        line
        for line in lines
        if (not ip or ip == line["ip"])
        and (not hostname or hostname == line["hostname"])
    ]


def write_hosts_file(hosts_fo: IO, lines: list[dict[str, str]]):
    """Write hosts file lines back to file"""
    lines.sort(key=sort_hosts_lines)
    hosts_fo.seek(0)
    hosts_fo.truncate()
    hosts_fo.writelines([f"{line['ip']}\t{line['hostname']}\n" for line in lines])


def dnsmasq_sighup():
    """Send SIGHUP to dnsmasq to reload configuration"""
    print("Send SIGHUP to dnsmasq...")
    subprocess.call(["pkill", "-SIGHUP", "dnsmasq"])


def sort_hosts_lines(item: dict):
    """Sort list by loopback first, ip second, hostname third"""
    return (
        not item["ip"].is_loopback,
        socket.inet_aton(str(item["ip"])),
        item["hostname"],
    )


def RecordNotFound(ip, hostname):
    """Return HTTPException for DNS record not found"""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"DNS record not found: ip={ip}, hostname={hostname}",
    )


def RecordAlreadyPresent(ip, hostname):
    """Return HTTPException for DNS record already present"""
    return HTTPException(
        status_code=status.HTTP_406_NOT_ACCEPTABLE,
        detail=f"DNS record already present: ip={ip}, hostname={hostname}",
    )


def validate_hostname(value: str):
    """Validate hostname format"""
    if not 1 <= len(value) < 64:
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
    """Model for creating DNS records"""

    ip: IPv4Address
    hostname: HOSTNAME


class DnsUpdate(BaseModel):
    """Model for updating DNS records"""

    ip: IPv4Address
    hostname: HOSTNAME


class DnsView(BaseModel):
    """Model for viewing DNS records"""

    ip: IPv4Address
    hostname: str


# API Router
dns_router = APIRouter(prefix="/dns", tags=["dns"])


@dns_router.get("", response_model=list[DnsView])
def dns_get_all() -> list[DnsView]:
    """Get all DNS records"""
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
    return hosts_lines


@dns_router.get("/{ip}/{hostname}", response_model=DnsView)
def dns_get(
    ip: IPv4Address,
    hostname: HOSTNAME,
) -> DnsView:
    """Get specific DNS record"""
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        hosts_lines = filter_hosts_file(hosts_lines, ip, hostname)
    if not hosts_lines:
        raise RecordNotFound(ip, hostname)
    return hosts_lines[0]


@dns_router.post("", response_model=list[DnsView])
def dns_add(
    dns_in: DnsCreate,
) -> list[DnsView]:
    """Add DNS record"""
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        if filter_hosts_file(hosts_lines, dns_in.ip, dns_in.hostname):
            raise RecordAlreadyPresent(dns_in.ip, dns_in.hostname)
        hosts_lines.append({"ip": dns_in.ip, "hostname": dns_in.hostname})
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines


@dns_router.put("/{ip}/{hostname}", response_model=list[DnsView])
def dns_update(
    ip: IPv4Address,
    hostname: HOSTNAME,
    dns_in: DnsUpdate,
) -> list[DnsView]:
    """Update DNS record"""
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


@dns_router.delete("/{ip}/{hostname}", response_model=list[DnsView])
def dns_delete(
    ip: IPv4Address,
    hostname: HOSTNAME,
) -> list[DnsView]:
    """Delete DNS record"""
    with get_hosts_file_object() as hosts_fo:
        hosts_lines = get_hosts_lines(hosts_fo)
        key = {"ip": ip, "hostname": hostname}
        if key not in hosts_lines:
            raise RecordNotFound(ip, hostname)
        hosts_lines.remove(key)
        write_hosts_file(hosts_fo, hosts_lines)
    dnsmasq_sighup()
    return hosts_lines
