import functools
import os
import re
import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.routing import APIRoute
from fastapi.security.api_key import APIKeyHeader

from zboxapi import __version__
from zboxapi.dns import dns_router
from zboxapi.vlan import vlan_router

api_key_header = APIKeyHeader(name="access_token", auto_error=False)


@functools.cache
def get_zpod_password() -> str:
    """Retrieve zpod password from VMware tools (cached after first lookup)"""
    ovfenv = subprocess.run(
        ["vmtoolsd", "--cmd", "info-get guestinfo.ovfenv"],
        capture_output=True,
        text=True,
    )
    pw_re = re.compile(r'<Property oe:key="guestinfo.password" oe:value="([^"]*)"/>')
    if item := re.search(pw_re, ovfenv.stdout):
        return item[1]
    raise Exception("Unable to retrieve zpod password")


def validate_api_key(api_key: Annotated[str | None, Security(api_key_header)]):
    """Validate API key for authentication"""
    if api_key != get_zpod_password():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid access_token",
        )


def generate_operation_id(route: APIRoute) -> str:
    """
    Build operation IDs as "<tag>_<function name>" so that generated API
    clients have simpler function names (e.g. dns_dns_get_all).
    """
    tag = route.tags[0] if route.tags else "default"
    return f"{tag}_{route.name}"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Resolve the zpod password at startup so a broken VM env fails fast"""
    get_zpod_password()
    yield


# Get root path from environment
zboxapi_root_path = os.getenv("ZBOXAPI_ROOT_PATH", None)

# Create FastAPI application
app = FastAPI(
    title="zBox API",
    root_path=zboxapi_root_path,
    dependencies=[Depends(validate_api_key)],
    version=__version__,
    lifespan=lifespan,
    generate_unique_id_function=generate_operation_id,
)

# Include routers
app.include_router(dns_router)
app.include_router(vlan_router)


def launch():
    """Launch the FastAPI application with uvicorn"""
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
    )


if __name__ == "__main__":
    launch()
