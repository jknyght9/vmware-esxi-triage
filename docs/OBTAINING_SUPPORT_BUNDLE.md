# Obtaining a Support Bundle from ESXi

This document describes how to generate and collect a VMware ESXi diagnostic support bundle for analysis.

## Methods

### 1. ESXi Host Client (Web UI)

1. Navigate to `https://<esxi-host>/ui`
2. Go to **Monitor** → **Logs**
3. Click **Generate support bundle**
4. Download the `.tgz` file when complete

### 2. SSH / ESXi Shell

Connect via SSH and run:

```bash
# Generate bundle (saved to /var/tmp/)
vm-support

# Generate with specific output location
vm-support --output /vmfs/volumes/datastore1/

# Generate without core dumps (smaller, faster)
vm-support --no-cores
```

### 3. vSphere Client (via vCenter)

1. Select the ESXi host in inventory
2. Go to **Monitor** → **Logs**
3. Click **Export System Logs**
4. Select the host and log types
5. Download the bundle

### 4. PowerCLI

```powershell
# Connect to vCenter or ESXi host
Connect-VIServer -Server <vcenter-or-esxi>

# Generate and download bundle
Get-VMHost -Name "esxi-host" | Get-Log -Bundle -DestinationPath "C:\Logs\"
```

### 5. vSphere CLI (Remote)

```bash
vicfg-support --server <esxi-host> --username root --output ./bundle.tgz
```

## Output Details

| Item | Details |
|------|---------|
| Default location | `/var/tmp/esx-<hostname>-<date>.tgz` |
| Typical size | 50MB - 500MB+ |
| Format | Gzipped tarball (`.tgz`) |

## Command Options

| Option | Description |
|--------|-------------|
| `--output <path>` | Specify output directory |
| `--no-cores` | Skip core dumps (faster, smaller bundle) |
| `--performance` | Include performance snapshots |
| `--duration <sec>` | Performance snapshot duration |

## Tips

- **Storage**: Ensure sufficient free space before generating
- **Performance**: Use `--no-cores` for faster collection when core dumps aren't needed
- **Forensics**: Collect the bundle **before** rebooting if investigating a security incident
- **Transfer**: Use SCP/SFTP to copy bundles from the host:
  ```bash
  scp root@<esxi-host>:/var/tmp/esx-*.tgz ./
  ```

## Bundle Contents

A support bundle typically includes:

- System logs (`/var/log/`, `/var/run/log/`)
- Configuration files (`/etc/vmware/`)
- Command output snapshots (`esxcli`, `esxtop`, etc.)
- Hardware and driver information
- VM configuration (`.vmx` files)
- Performance data (if requested)

## Troubleshooting

**Bundle generation fails:**
- Check available space: `df -h`
- Try with `--no-cores` option
- Check `/var/log/vmkernel.log` for errors

**Bundle is very large:**
- Use `--no-cores` to exclude memory dumps
- Clear old logs before generating: `esxcli system syslog reload`

**Cannot SSH to host:**
- Enable SSH: Host Client → Manage → Services → TSM-SSH → Start
- Or via DCUI: Troubleshooting Options → Enable SSH
