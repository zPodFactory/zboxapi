# Disk and Storage Management API

zboxapi can turn a disk added to the zcore VM into a mounted `/FILER/STORAGEnn`, grow it after
the virtual disk was enlarged in vSphere, manage the top-level folders on it, and take it out
of service again. Three routers:

| Router | Manages |
|---|---|
| `/disk` | block devices: what is attached, what state each is in, rescan |
| `/storage` | filesystems mounted at `/FILER/STORAGEnn`, raw or LVM, and their folders |
| `/nfs` | exports, see [DOC_NFS.md](DOC_NFS.md) |

## The guard rail

**NFS-01, `/FILER/STORAGE01` and the whole disk behind it are never modified.** The one
exception is growing: rescan, `growpart`, `pvresize`, `lvextend` and `resize2fs` only add space
and move no data, so `POST /storage/STORAGE01/grow` works. Everything else on that disk is
refused, as is anything on the system disk (the one holding `/`, `/boot` or swap).

The protected set is computed on every request from the live mount: the mountpoint of each
protected storage, its source device, the parent disk, every partition of that disk, every
PV/VG/LV backed by it, and the protected export paths with everything under them. It follows
the mount, so a disk letter change after adding disks cannot move the protection. STORAGE01
and NFS-01 are a floor that configuration can add to but never remove.

It is enforced three times, independently:

1. at every mutating endpoint, which answers **403** with the reason;
2. inside the single command runner, which refuses to execute any command naming a protected
   device, VG, LV or path, except the exact extend-only shapes above and read-only commands;
3. in the file writers, which refuse a protected path.

Other folders and exports on STORAGE01 (NFS-02, NFS-VCD, a new NFS-06) are ordinary and can be
created, changed and deleted.

## Configuration

Every key has a default; the `[storage]` section of `/etc/zboxapi.conf` is optional.

```ini
[storage]
filer_root = /FILER
protected_storages = STORAGE01          # comma-separated; STORAGE01 is always included
mount_unit_dir = /etc/systemd/system
filesystem = ext4
mkfs_options = -m 0 -E lazy_itable_init=0,lazy_journal_init=0
mount_options = defaults,noatime,nofail
```

## Disks

### State

Every disk is classified live from `lsblk`, never from a cache:

| State | Rule | The API may |
|---|---|---|
| `system` | holds `/`, `/boot` or swap | read |
| `protected` | holds the mountpoint of a protected storage | read, rescan, grow |
| `blank` | no partition table and no filesystem signature | create a storage on it |
| `foreign` | partitions or a signature the API did not create | read; wipe it by hand first |
| `in-use` | backs a storage mounted under `/FILER` | grow, remove the storage |

There is no force flag: a disk with anything on it is never formatted by this API.

### 1. List disks
**GET** `/disk`

```json
[
  {
    "name": "sdb", "path": "/dev/sdb", "size": 1099511627776, "size_human": "1.0T",
    "model": "Virtual disk", "serial": "6000c29...", "pttype": "gpt",
    "state": "protected", "reason": "sdb is protected: it holds /FILER/STORAGE01 (STORAGE01)",
    "partitions": [
      {"name": "sdb1", "path": "/dev/sdb1", "size": 1099509530624, "size_human": "1024.0G",
       "fstype": "ext4", "label": null, "uuid": "9f0c…", "mountpoint": "/FILER/STORAGE01"}
    ],
    "storage": "STORAGE01"
  },
  {
    "name": "sdc", "path": "/dev/sdc", "size": 536870912000, "size_human": "500.0G",
    "model": "Virtual disk", "serial": "6000c29...", "pttype": null,
    "state": "blank", "reason": "sdc has no partition table and no filesystem signature",
    "partitions": [], "storage": null
  }
]
```

### 2. Get one disk
**GET** `/disk/{name}`

### 3. Rescan
**POST** `/disk/rescan`

Scans the SCSI hosts for disks attached since boot, then re-reads the size of every disk from
the hypervisor. Both are reads; nothing on any disk changes.

```json
{
  "new": ["sdc"],
  "resized": [
    {"disk": "sdd", "before": 2199023255552, "after": 4398046511104,
     "before_human": "2.0T", "after_human": "4.0T", "storage": "STORAGE03"}
  ]
}
```

## Storages

A storage is one filesystem on one disk, mounted at `/FILER/STORAGEnn`. Two layouts:

- **raw**: `/dev/sdX1` carries the filesystem;
- **lvm**: `/dev/sdX1` is a PV in `vg_storagenn`, with one LV `data`, which carries it.

Both start with a GPT label and a single partition, so growing works the same way. A storage
the API created has a systemd mount unit (`/etc/systemd/system/FILER-STORAGEnn.mount`) and is
`managed: true`. One mounted by hand through `/etc/fstab`, like STORAGE01, is `managed: false`:
it accepts folders, exports and grow, but not `DELETE /storage`.

### Operations, dry run and verbose

Create, adopt, grow and delete run as a plan of named steps and answer with it:

```json
{
  "operation": "storage_create",
  "dry_run": false,
  "steps": [
    {"step": "partition",  "target": "/dev/sdc",          "detail": "GPT label, one Linux LVM partition", "status": "done"},
    {"step": "settle",     "target": "/dev/sdc",          "detail": "wait for udev, re-read the partition table", "status": "done"},
    {"step": "partx",      "target": "/dev/sdc",          "detail": "tell the kernel about the new partition", "status": "done"},
    {"step": "pv",         "target": "/dev/sdc1",         "detail": "physical volume", "status": "done"},
    {"step": "vg",         "target": "vg_storage02",      "detail": "volume group on /dev/sdc1", "status": "done"},
    {"step": "lv",         "target": "/dev/vg_storage02/data", "detail": "logical volume data, all free space", "status": "done"},
    {"step": "mkfs",       "target": "/dev/vg_storage02/data", "detail": "ext4, label STORAGE02", "status": "done"},
    {"step": "mountpoint", "target": "/FILER/STORAGE02",  "detail": "create the mount point", "status": "done"},
    {"step": "mount-unit", "target": "FILER-STORAGE02.mount", "detail": "systemd mount unit, What=UUID=3c1f…", "status": "done"},
    {"step": "daemon-reload", "target": "systemd",        "detail": "load the new unit", "status": "done"},
    {"step": "mount",      "target": "/FILER/STORAGE02",  "detail": "enable and start FILER-STORAGE02.mount", "status": "done"}
  ],
  "storage": { "name": "STORAGE02", "layout": "lvm", "...": "..." }
}
```

Two query parameters on each of them:

- `?dry_run=true` returns the same steps with status `planned` and runs nothing;
- `?verbose=true` adds the exact `command` and its `output` to every step.

The commands always go to `/var/log/zboxapi-storage.log`. Statuses are `planned`, `done`,
`nochange`, `failed` and `skipped`. When a step fails, the steps already done are reverted
in reverse order and the 500 response carries `message`, `steps` and `rollback`.

### 1. List storages
**GET** `/storage`

### 2. Get one storage
**GET** `/storage/{name}`

```json
{
  "name": "STORAGE02",
  "mountpoint": "/FILER/STORAGE02",
  "disk": "sdc",
  "device": "/dev/mapper/vg_storage02-data",
  "layout": "lvm",
  "vg": "vg_storage02",
  "lv": "data",
  "fstype": "ext4",
  "uuid": "3c1f…",
  "size": 527430156288, "used": 28672, "avail": 527430127616,
  "size_human": "491.2G", "used_human": "28.0K", "avail_human": "491.2G",
  "protected": false,
  "managed": true,
  "exports": 1,
  "folders": [
    {"name": "NFS-15", "path": "/FILER/STORAGE02/NFS-15", "exported": true,
     "protected": false, "empty": false, "mode": "0777", "owner": "root:root"}
  ]
}
```

### 3. Create a storage on a blank disk
**POST** `/storage`

```json
{ "disk": "sdc", "lvm": true, "name": "STORAGE02" }
```

`name` is optional and defaults to the next free number. `lvm` defaults to false.

Steps: `sfdisk` writes a GPT label with one partition (type Linux filesystem, or Linux LVM),
`udevadm settle` and `partx -u` make the kernel see it, then for LVM `pvcreate`, `vgcreate
vg_storagenn`, `lvcreate -l 100%FREE -n data`; `mkfs.ext4` with the label `STORAGEnn` and a
pre-generated UUID; the mount point; the mount unit; `systemctl daemon-reload` and
`systemctl enable --now`. If any step fails, everything done so far is undone and the disk is
blank again.

Refused with 403 for a protected or system disk, 404 for an unknown disk, 409 for a disk that
is not blank, a name already in use or a non-empty mount point, 400 for `lvm: true` when the
`lvm2` package is not installed (raw still works).

### 4. Adopt an existing filesystem
**POST** `/storage/adopt`

```json
{ "device": "sdd1", "name": "STORAGE03" }
```

`device` is a partition (`sdd1`, `/dev/sdd1`) or an LV (`vg_old/data`). The filesystem must be
ext4, carry a UUID and not be mounted anywhere. Only the mount point, the unit and the mount
are created; **nothing is formatted**. This is how a disk taken out with `DELETE /storage` comes
back, and how a filesystem prepared by hand joins the convention.

### 5. Grow a storage
**POST** `/storage/{name}/grow`

After the virtual disk was enlarged in vSphere. Every step is online; clients keep working.

```json
{
  "operation": "storage_grow",
  "dry_run": false,
  "changed": true,
  "before": {"disk": 536870912000, "partition": 536868814848, "lv": 536864620544, "filesystem": 527430156288},
  "after":  {"disk": 1099511627776, "partition": 1099509530624, "lv": 1099505336320, "filesystem": 1081103286272},
  "steps": [
    {"step": "rescan",    "target": "/dev/sdc",  "detail": "re-read the disk size from the hypervisor", "status": "done"},
    {"step": "growpart",  "target": "/dev/sdc1", "detail": "extend the partition to the end of the disk", "status": "done"},
    {"step": "pvresize",  "target": "/dev/sdc1", "detail": "extend the physical volume", "status": "done"},
    {"step": "lvextend",  "target": "/dev/mapper/vg_storage02-data", "detail": "extend the logical volume to all free space", "status": "done"},
    {"step": "resize2fs", "target": "/dev/mapper/vg_storage02-data", "detail": "grow the filesystem online", "status": "done"}
  ],
  "storage": { "...": "..." }
}
```

A raw storage has no `pvresize` and `lvextend` steps. Calling it when nothing grew is not an
error: `growpart` and `lvextend` report `nochange` and `changed` is false. STORAGE01 is allowed
here, as the one exception to the guard rail. A failing step answers 500 with
`Cannot grow NAME: <step> on <target> failed: <error>`; nothing is rolled back because nothing
was changed that cannot simply be retried.

### 6. Remove a storage
**DELETE** `/storage/{name}`

Only when the storage has no exports and was mounted by this API. It is unmounted, its unit
removed, its empty mount point removed. **The filesystem, the LVM objects and the disk stay as
they are**: the disk then shows as `foreign`, and `POST /storage/adopt` brings it back. Reusing
the disk for a fresh storage needs a wipe by hand first.

Refused with 403 for STORAGE01, 409 when exports exist (the message lists them) or when the
storage has no unit file, 404 when it does not exist.

## Folders

The top-level directories of a storage, listed in `GET /storage/{name}` as `folders`. The API
never goes deeper than one level.

### 7. Create a folder
**POST** `/storage/{name}/{folder}`

```json
{ "owner": "root:root", "mode": "0777" }
```

The body is optional; both values default to the `[nfs]` configuration. `owner` is
`user:group`, names or numeric ids, and both must exist on zcore. `mode` is octal.

### 8. Change ownership or permissions
**PUT** `/storage/{name}/{folder}`

```json
{ "owner": "root:root", "mode": "0770", "recursive": true }
```

`chown` and/or `chmod` on the folder; with `recursive: true` on everything below it as well.
Symbolic links are changed, never followed. Give at least one of `owner` and `mode`.

### 9. Delete a folder
**DELETE** `/storage/{name}/{folder}` and `DELETE /storage/{name}/{folder}?force=true`

Without `force`, only an empty folder is deleted. With `force=true`, the folder and everything
in it are removed and the response says how many entries went. In both cases an **exported**
folder is refused with 409 until its export is deleted (clients may still have it mounted), and
NFS-01 is refused with 403.

```json
{
  "message": "Folder /FILER/STORAGE02/NFS-15 deleted with 13 entries",
  "path": "/FILER/STORAGE02/NFS-15",
  "removed": 14,
  "forced": true
}
```

## What zcore needs

All in the appliance already, except `lvm2`, which packer-zcore now installs:

| Tool | Package |
|---|---|
| sfdisk | fdisk |
| wipefs, blkid, lsblk, findmnt, partx | util-linux |
| mkfs.ext4, resize2fs | e2fsprogs |
| growpart | cloud-guest-utils |
| pvcreate, vgcreate, lvcreate, pvresize, lvextend | lvm2 |
| exportfs | nfs-kernel-server |

Without `lvm2`, `lvm: true` answers 400 and raw storages work.

## Files

```
/etc/systemd/system/FILER-STORAGEnn.mount   one unit per storage the API created, What=UUID=…
/FILER/STORAGEnn                            the mount point
/var/log/zboxapi-storage.log                every command and file change, with exit status
/run/zboxapi-storage.lock                   one lock for every mutating storage and nfs call
```

## Error Handling

- **400 Bad Request**: a precondition on the host (`lvm2` missing, storage not mounted)
- **403 Forbidden**: a protected or system disk, STORAGE01, NFS-01
- **404 Not Found**: unknown disk, storage, folder or device
- **409 Conflict**: disk not blank, name taken, mount point not empty, folder not empty or
  exported, storage with exports or without a unit
- **422 Unprocessable Content**: invalid name, owner, mode or body
- **500 Internal Server Error**: a step failed; the response lists the steps and the rollback
