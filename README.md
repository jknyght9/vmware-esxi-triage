# ESXi Support Bundle Triage Tool

A pure bash script that analyzes VMware ESXi diagnostic support bundles and extracts configuration, diagnostic, and security forensics information.

## Features

- **Host Information**: ESXi version, hostname, DNS configuration
- **Infrastructure**: vCenter management status, vSAN detection
- **Storage**: VMFS, NFS, iSCSI configurations
- **Networking**: VMkernel NICs, vSwitches, portgroups, firewall rules
- **Log Forwarding**: Remote syslog configuration
- **Security Forensics**: Ransomware indicators, VM escape CVEs, persistence mechanisms

## Supported ESXi Versions

| Version | Log Location | Status |
|---------|--------------|--------|
| ESXi 6.0 | `/var/log/` | Supported |
| ESXi 6.5, 6.7 | `/var/run/log/` | Supported |
| ESXi 7.x | `/var/run/log/` | Supported |
| ESXi 8.x | `/var/run/log/` | Supported |

The script auto-detects log locations.

## Obtaining a Support Bundle

See [Obtaining a Support Bundle](docs/OBTAINING_SUPPORT_BUNDLE.md) for detailed instructions on generating support bundles via:
- ESXi Host Client (Web UI)
- SSH / ESXi Shell (`vm-support`)
- vSphere Client (vCenter)
- PowerCLI
- vSphere CLI

## Usage

```bash
# Analyze a compressed bundle
./esx_bundle_triage.sh vm-support-*.tgz

# Analyze an extracted directory
./esx_bundle_triage.sh /path/to/extracted/bundle
```

## Output

Results are written to `./triage-output-YYYYmmdd-HHMMSS/`:

- `report.txt` - Human-readable text report
- `report.json` - Machine-parseable JSON output

## Report Sections

### Host Information
- ESXi version and build number
- System UUID and installation date
- Hostname and FQDN
- Management IP address
- VIB acceptance level
- DNS servers and search domains
- `/etc/hosts` entries
- `/etc/resolv.conf` contents

### vCenter Management
- Managed status (YES/LIKELY/NO)
- vCenter hostname and IP
- Evidence sources

### Storage Configuration
- VMFS datastores and extents
- NFS mounts
- iSCSI adapters

### Networking
- Physical NICs (pNICs) with MAC addresses
- VMkernel interfaces (vmk) with IP configuration
- Standard and Distributed vSwitches
- Port groups with VLAN assignments
- Firewall rulesets

### Security Forensics

The tool performs security analysis to detect indicators of compromise. See [Security Detection](docs/SECURITY_DETECTION.md) for detailed documentation.

**Ransomware Detection**
- Encrypted file extensions (`.babyk`, `.royal`, `.blackbasta`, `.esxiargs`, etc.)
- Ransom note files
- Suspicious scripts in `/tmp/` and `/scratch/`
- Malicious startup scripts

**VM Escape / CVE Detection**
- OpenSLP vulnerabilities (CVE-2019-5544, CVE-2020-3992)
- VMCI/vSock issues (CVE-2022-31696)
- USB controller exploits (CVE-2024-22252/22253/22254)
- AD authentication bypass (CVE-2024-37085)
- UNC3886 APT indicators

**Persistence Mechanisms**
- Malicious VIB detection
- Startup script analysis
- Cron job detection

## Dependencies

Pure bash with standard Unix tools only:
- `find`, `grep`, `sed`, `head`, `tar`, `mktemp`

No external packages required.

## JSON Schema

```json
{
  "input": "path/to/bundle",
  "root": "extracted/path",
  "esxi": {
    "hostname": "esxi-host.domain.com",
    "domain": "domain.com",
    "version": "6.7.0",
    "build": "12345678",
    "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "inception": "2020-01-14T22:26:01",
    "vib_acceptance_level": "partner",
    "management_ip": "10.0.0.100"
  },
  "dns": {
    "servers": ["10.0.0.1", "10.0.0.2"],
    "search_domains": ["domain.com"],
    "hosts_entries": ["127.0.0.1 localhost"]
  },
  "vcenter": {
    "managed": "YES",
    "hostname": "vcenter.domain.com",
    "ip": "10.0.0.10"
  },
  "vsan": {
    "indicated": "YES|LIKELY|POSSIBLE|NO_EVIDENCE"
  },
  "security": {
    "ransomware": {
      "confidence": "NONE|LOW|MEDIUM|HIGH",
      "encrypted_files": [],
      "ransom_notes": [],
      "suspicious_scripts": []
    },
    "vm_escape": {
      "confidence": "NONE|LOW|MEDIUM|HIGH|CRITICAL",
      "cve_indicators": []
    },
    "persistence": {
      "startup_scripts": [],
      "suspicious_vibs": []
    },
    "config_findings": []
  }
}
```

## License

MIT
