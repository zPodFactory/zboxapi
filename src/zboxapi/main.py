import os
import re
import subprocess
from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.routing import APIRoute
from fastapi.security.api_key import APIKey, APIKeyHeader

from zboxapi import __version__
from zboxapi.dns import dns_router
from zboxapi.vlan import vlan_router

api_key_header = APIKeyHeader(name="access_token", auto_error=False)


def validate_api_key(api_key: Annotated[APIKey, Security(api_key_header)]):
    """Validate API key for authentication"""
    if api_key != ZPOD_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid access_token",
        )


def get_zpod_password():
    """Retrieve zpod password from VMware tools"""
    ovfenv = subprocess.run(
        ["vmtoolsd", "--cmd", "info-get guestinfo.ovfenv"],
        capture_output=True,
        text=True,
    )
    pw_re = re.compile(r'<Property oe:key="guestinfo.password" oe:value="([^"]*)"/>')
    if item := re.search(pw_re, ovfenv.stdout):
        return item[1]
    raise Exception("Unable to retrieve zpod password")


def simplify_operation_ids(api: FastAPI) -> None:
    """
    Update operation IDs so that generated API clients have simpler function
    names.
    """
    for route in api.routes:
        if isinstance(route, APIRoute) and not route.operation_id:
            tag = route.tags[0] if route.tags else "default"
            route.operation_id = f"{tag}_{route.name}"


# Get zpod password for authentication
ZPOD_PASSWORD = get_zpod_password()

# Get root path from environment
zboxapi_root_path = os.getenv("ZBOXAPI_ROOT_PATH", None)

# Create FastAPI application
app = FastAPI(
    title="zBox API",
    root_path=zboxapi_root_path,
    dependencies=[Depends(validate_api_key)],
    version=__version__,
)

# Include routers
app.include_router(dns_router)
app.include_router(vlan_router)

# Simplify operation IDs
simplify_operation_ids(app)


def launch():
    """Launch the FastAPI application with uvicorn"""
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
    )


if __name__ == "__main__":
    launch()
