# NFS Export Management API

zboxapi manages NFS exports on the zcore filer: which folder under `/FILER/STORAGEnn` is
exported to which clients. It writes one file of its own, `/etc/exports.d/zboxapi.exports`,
and reloads the NFS server with `exportfs -ra`. The exports zcore-init created in
`/etc/exports` stay visible and untouched.

One rule above all others: **`/FILER/STORAGE01/NFS-01` is never modified**. Not exported
differently, not unexported, not deleted, not re-owned. See [DOC_STORAGE.md](DOC_STORAGE.md)
for the full guard rail, which also covers the STORAGE01 mount and the disk behind it.

## Configuration

Every key has a default; the `[nfs]` section of `/etc/zboxapi.conf` is optional.

```ini
[nfs]
# The file this API writes; exportfs -ra reads /etc/exports.d/*.exports natively
exports_file = /etc/exports.d/zboxapi.exports

# Read-only to the API: its lines are listed with owner "system"
system_exports_file = /etc/exports

# Never modified, whatever the request (comma-separated; NFS-01 is always included)
protected_exports = /FILER/STORAGE01/NFS-01

# Options every client of an export gets; what zcore-init gives NFS-VCD
export_options = rw,no_subtree_check,no_root_squash

# Owner and mode of a folder the API creates (what NFS-01 has today)
folder_owner = root:root
folder_mode = 0777
```

## The model

An export is a path `/FILER/<STORAGE>/<FOLDER>` plus a list of clients. Every client gets the
same options from `export_options`. A client is an IPv4 address (`10.60.60.10`), an IPv4
network in CIDR notation (`10.60.60.0/26`) or `*` for everyone, which `exportfs` prints as
`<world>`. Hostnames and IPv6 are rejected.

Two owners:

| Owner | Where the line lives | The API may |
|---|---|---|
| `system` | `/etc/exports` (written by zcore-init) | list it. Every change answers 403. |
| `user-defined` | `/etc/exports.d/zboxapi.exports` | create, change clients, delete |

Today that makes NFS-01 to NFS-05 and NFS-VCD `system`. Moving a line from `/etc/exports` into
the managed file by hand makes it `user-defined`; that is a human decision, not an API call.

## API Endpoints

### 1. List all exports
**GET** `/nfs`

Merges both files with the live `exportfs -v`.

```json
[
  {
    "path": "/FILER/STORAGE01/NFS-01",
    "storage": "STORAGE01",
    "folder": "NFS-01",
    "clients": [{"client": "10.60.60.0/26", "options": "rw,no_subtree_check"}],
    "owner": "system",
    "protected": true,
    "active": true,
    "folder_exists": true
  },
  {
    "path": "/FILER/STORAGE02/NFS-15",
    "storage": "STORAGE02",
    "folder": "NFS-15",
    "clients": [{"client": "10.60.60.0/26", "options": "rw,no_subtree_check,no_root_squash"}],
    "owner": "user-defined",
    "protected": false,
    "active": true,
    "folder_exists": true
  }
]
```

`active` is false when the line is in a file but `exportfs` does not currently serve it.
`folder_exists` is false when the directory was removed by hand. A path outside the
`/FILER/STORAGEnn/FOLDER` convention is listed with `storage` and `folder` set to `null`.

### 2. Get one export
**GET** `/nfs/{storage}/{folder}`

One entry of the list above, or 404.

### 3. Create an export
**POST** `/nfs`

```json
{
  "storage": "STORAGE02",
  "folder": "NFS-15",
  "clients": ["10.60.60.0/26", "192.168.0.10"]
}
```

The folder is created with `folder_owner` and `folder_mode` when it does not exist, and left
exactly as it is when it does. The line is appended to the managed file, which is replaced
atomically, then `exportfs -ra` runs. The response is the export as in the list.

Refused with:
- 400 when the storage is not mounted under `/FILER`
- 403 when the path is NFS-01 or already exported by `/etc/exports`
- 409 when the path is already exported by the managed file
- 422 for an invalid client, an empty or duplicated client list, or a bad name

### 4. Replace the clients
**PUT** `/nfs/{storage}/{folder}`

```json
{ "clients": ["192.168.0.0/24", "*"] }
```

### 5. Add one client
**POST** `/nfs/{storage}/{folder}/client`

```json
{ "client": "192.168.0.0/24" }
```

409 when the client is already in the list.

### 6. Remove one client
**DELETE** `/nfs/{storage}/{folder}/client/{client}`

The slash of a CIDR may be sent as is or encoded: `/nfs/STORAGE02/NFS-15/client/10.60.60.0/26`
and `.../client/10.60.60.0%2F26` are the same call. Removing the last client removes the
export, and the response says so:

```json
{
  "message": "192.168.0.0/24 was the last client: /FILER/STORAGE02/NFS-15 is no longer exported; the folder and its data stay",
  "path": "/FILER/STORAGE02/NFS-15",
  "folder_kept": true
}
```

### 7. Delete an export
**DELETE** `/nfs/{storage}/{folder}`

Removes the line and reloads. **The folder and its data always stay.** Deleting data is a
separate decision, made with `DELETE /storage/{storage}/{folder}?force=true` (see
[DOC_STORAGE.md](DOC_STORAGE.md)).

```json
{
  "message": "/FILER/STORAGE02/NFS-15 is no longer exported; the folder and its data stay",
  "path": "/FILER/STORAGE02/NFS-15",
  "folder_kept": true
}
```

## Validation Rules

- **Storage name**: `STORAGE` followed by two or three digits (`STORAGE02`, `STORAGE123`).
- **Folder name**: letters, digits, `.`, `_` and `-`, 63 characters at most, must start with a
  letter or digit, no path separators. `grow`, `adopt` and `folder` are reserved.
- **Client**: IPv4 address, IPv4 network in CIDR notation, or `*`. At least one, no duplicates.

## Files

```
/etc/exports                        zcore-init's exports, owner system, read-only to the API
/etc/exports.d/zboxapi.exports      the managed file, one line per export:
                                    /FILER/STORAGE02/NFS-15 10.60.60.0/26(rw,no_subtree_check,no_root_squash) 192.168.0.10(rw,no_subtree_check,no_root_squash)
/var/log/zboxapi-storage.log        every change, with the command that ran and its exit status
```

The managed file is rewritten in full on every change: temp file in the same directory,
fsync, rename into place, mode 0644. A crash mid-write leaves the previous file intact.

## Error Handling

- **400 Bad Request**: the storage is not mounted
- **403 Forbidden**: NFS-01, or any export that lives in `/etc/exports`
- **404 Not Found**: no such export, or no such client on it
- **409 Conflict**: already exported, client already present
- **422 Unprocessable Content**: invalid client, name or empty list
- **500 Internal Server Error**: `exportfs` or a file operation failed; the message says which
