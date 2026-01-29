# Security Detection Reference

This document details the security forensics detection capabilities of the ESXi Support Bundle Triage Tool.

## Confidence Levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Multiple corroborating indicators or known malicious artifacts |
| **HIGH** | Strong CVE-specific indicator or confirmed ransomware evidence |
| **MEDIUM** | Suspicious patterns requiring investigation |
| **LOW** | Anomalies that may warrant manual review |
| **NONE** | No indicators detected |

---

## Ransomware Detection

### Encrypted File Extensions

The tool searches for files with known ransomware extensions:

| Extension | Associated Ransomware |
|-----------|----------------------|
| `.babyk` | Babuk |
| `.royal` | Royal |
| `.blackbasta` | Black Basta |
| `.esxiargs` | ESXiArgs |
| `.akira` | Akira |
| `.blackcat` / `.alphv` | BlackCat/ALPHV |
| `.encrypted` | Generic |
| `.locked` | Generic |
| `.crypted` | Generic |
| `.enc` | Generic |
| `.crypt` | Generic |
| `.siege` | Siege |

### Ransom Note Detection

Searches for common ransom note filenames:

- `HOW_TO_RESTORE*.txt`
- `HOW_TO_DECRYPT*.txt`
- `README_TO_RESTORE*.txt`
- `RECOVER*.txt`
- `DECRYPT*.txt`
- `!README!.txt`
- `ransom*.txt`
- `restore_files*.txt`
- `*_readme.txt`
- `unlock*.txt`

### Suspicious Scripts

Detects potentially malicious scripts and binaries:

**Locations checked:**
- `/tmp/`
- `/scratch/`
- `/etc/rc.local.d/`

**File patterns:**
- Shell scripts (`.sh`) in temporary directories
- ELF binaries in non-standard locations
- Known malicious names: `encrypt.sh`, `ksmd`, `tools`, `update`, `autobackup.bin`

### Startup Script Persistence

**`vmware_local.sh` in `/etc/rc.local.d/`**
- Known indicator of malicious VIB installation
- Confidence: **HIGH**

**Non-standard scripts in `/etc/rc.local.d/`**
- Any `.sh` file other than `local.sh`
- Confidence: **LOW** (requires manual review)

---

## VM Escape / CVE Detection

### CVE-2019-5544 / CVE-2020-3992 (OpenSLP)

**Vulnerability:** Heap overflow in OpenSLP service

**Detection patterns in vmkernel.log:**
```
slp|slpd|port.427|openslp
```

**Firewall check:**
- Port 427 (SLP) enabled in firewall rules

**Confidence:** HIGH

**Mitigation:** Disable SLP service (disabled by default in ESXi 7.0 U2c+ and 8.0+)

---

### CVE-2021-22045 (CD-ROM Heap Overflow)

**Vulnerability:** Heap overflow in CD-ROM device emulation

**Detection patterns in vmkernel.log:**
```
cdrom.*error|cd-rom.*overflow|ide.*overflow
```

**Confidence:** MEDIUM

---

### CVE-2022-31696 (VMCI/vSock)

**Vulnerability:** Memory corruption in VMCI/vSock

**Detection patterns in vmkernel.log:**
```
vmci.*error|vsock.*error|heap.overflow|memory.corruption
```

**Confidence:** HIGH

---

### CVE-2023-20867 (VMware Tools Guest Operations)

**Vulnerability:** Authentication bypass in VMware Tools guest operations

**Detection patterns in hostd.log:**
```
Guest.*Operation.*Failed|GuestOperation|vmtoolsd.*error
```

**Confidence:** MEDIUM

**Associated threat:** UNC3886 APT group

---

### CVE-2024-22252 / CVE-2024-22253 / CVE-2024-22254 (USB Controller)

**Vulnerability:** Use-after-free in USB UHCI/XHCI controller

**Affected versions:** ESXi 7.x, 8.x

**Detection patterns in vmkernel.log:**
```
uhci.*error|xhci.*error|usb.*overflow|usb.*corrupt|vmx.*usb.*exception
```

**Confidence:** HIGH

---

### CVE-2024-37085 (AD Authentication Bypass)

**Vulnerability:** AD group "ESX Admins" grants full admin access

**Detection patterns in auth.log:**
```
ESX.Admins|esx.*admin.*group|domain.*admin|AD.*group.*added
```

**Detection patterns in esx.conf:**
```
ActiveDirectory|LDAP|domain.*join|ESX.*Admins
```

**Confidence:** CRITICAL (if ESX Admins group manipulation detected)

---

### Sandbox Escape Indicators (ESXi 8.x)

**Detection patterns in vmkernel.log:**
```
sandbox.*escape|vmx.*sandbox|sandboxed.*process.*exit
```

**Confidence:** CRITICAL

---

### execInstalledOnly Violation

**Description:** Unsigned code execution attempted on ESXi host

**Detection patterns in vmkernel.log:**
```
execInstalledOnly.*violation|unsigned.*execution
```

**Confidence:** CRITICAL

---

### UNC3886 APT Indicators

**Threat:** Chinese state-sponsored APT targeting VMware infrastructure

**Detection patterns in vpxa.log:**
```
pyvmomi|Python.*Linux|python.*vmware
```

**Confidence:** MEDIUM

**Note:** pyvmomi is legitimate automation tooling, but unexpected usage warrants investigation

---

## Persistence Mechanism Detection

### Malicious VIB Detection

**VIB acceptance levels checked:**
- `CommunitySupported` - Not signed by VMware
- `PartnerSupported` - Third-party signed

**Known malicious VIB names:**
- `virtualpita`
- `virtualpie`
- `virtualgate`
- `vmsync`
- `vmtools-backdoor`

**Confidence:** CRITICAL (if known malicious VIB found)

### Startup Script Analysis

**Files checked:**
- `/etc/rc.local.d/*.sh`
- `/etc/rc.local.d/local.sh` (for suspicious additions)

**Suspicious patterns in local.sh:**
```
wget|curl|chmod|python|perl|/tmp/|/scratch/|base64|nc|netcat
```

### Cron Job Detection

**Directories checked:**
- `/var/spool/cron/`
- `/etc/cron.d/`

### Hidden Files in VMFS

Detects hidden files (starting with `.`) in VMFS volumes:
```
/vmfs/volumes/*/.*
```

### Configuration File Tampering

**`/etc/vmware/config` checks:**
```
libdir|execpath|preload
```

These entries could indicate library injection attacks.

---

## Additional Security Checks

### Authentication Anomalies

**Brute force detection in auth.log:**
- Counts failed authentication attempts
- Threshold: >50 failures triggers alert
- Confidence: MEDIUM

### Shell Access Abuse

**Patterns in shell.log:**
```
ESXShell.*enable|SSH.*enable|TSM.*enable
```

**Followed by suspicious commands:**
```
wget|curl|chmod|/tmp/|python|perl|nc|netcat|base64
```

---

## References

- [VMware Security Advisories](https://www.vmware.com/security/advisories.html)
- [Mandiant UNC3886 Report](https://www.mandiant.com/resources/blog/esxi-hypervisors-malware-persistence)
- [CISA ESXiArgs Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-039a)
