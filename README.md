# WDSEnum

**WDSEnum** is a tool for enumerating and retrieving unattend files from Windows Deployment Services (WDS). 

It implements [WDSC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wdsc/387513a6-7bf5-4e86-9524-919ce3318bbf) and [WDSOSD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wdsosd/b44c3aa3-bd54-44e2-82b8-ca1d91e62fd3) to interact with WDS over RPC.

## Installation

### Install with pip

```bash
git clone "https://github.com/cogiceo/WDSEnum"
cd wdsenum
pip install .
```

### Install with pipx

```bash
pipx install "git+https://github.com/cogiceo/WDSEnum"
```

## Unauthenticated

Using RPC, an unauthenticated user can retrieve architecture-specific unattend files as well as custom unattend files linked to a device ID (GUID, DUID, MAC).

### Architecture-specific

```bash
wdsenum unattend-noauth -o $OUTPUT_FOLDER -t $TARGET --arch
```

### Custom unattend file based on device ID

```bash
wdsenum unattend-noauth -o $OUT_FOLDER -t $TARGET --id '{00000000-0000-0000-0000-000000000000}'  # GUID
wdsenum unattend-noauth -o $OUT_FOLDER -t $TARGET --id '00-00-00-00-00-00-00-00-00-00'           # DUID
wdsenum unattend-noauth -o $OUT_FOLDER -t $TARGET --id '00-00-00-00-00-00'                       # MAC
```

## Authenticated


```bash
wdsenum unattend -o $OUT_FOLDER -i $DC_HOST -d $DOMAIN -u $USER -p $PASSWORD
```

The authenticated enumeration process is as follows:

- Enumerates WDS servers and prestaged computers that have custom unattend files through LDAP.
- Retrieves architecture-specific unattend files from discovered WDS servers.
- If prestaged computers with custom unattend files are found, retrieves their unattend files using the device IDs obtained from LDAP.
- Retrieves "install images" unattend files using SMB, as they are readable by authenticated users on the `REMINST` share by default.
