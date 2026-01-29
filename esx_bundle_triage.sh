#!/usr/bin/env bash
set -euo pipefail

# --------------------------------------------
# ESXi Support Bundle Triage Tool
#
# Analyzes VMware ESXi diagnostic support bundles for:
#   - Host configuration (version, hostname, DNS, vCenter)
#   - Storage and networking configuration
#   - Security forensics (ransomware, VM escape CVEs, persistence)
#
# Supported ESXi versions:
#   - ESXi 6.0 (logs in /var/log/)
#   - ESXi 6.5+ (6.5, 6.7, 7.x, 8.x - logs in /var/run/log/)
#   Note: Script auto-detects log location
#
# Usage:
#   ./esx_bundle_triage.sh <bundle.tgz | extracted_dir>
#
# Output:
#   ./triage-output-YYYYmmdd-HHMMSS/report.txt
#   ./triage-output-YYYYmmdd-HHMMSS/report.json
#
# See README.md for full documentation
# --------------------------------------------

INPUT="${1:-}"
if [[ -z "${INPUT}" ]]; then
  echo "Usage: $0 <vm-support-bundle.tgz | extracted_bundle_dir>"
  exit 1
fi

ts="$(date +%Y%m%d-%H%M%S)"
OUTDIR="./triage-output-${ts}"
mkdir -p "${OUTDIR}"
REPORT_TXT="${OUTDIR}/report.txt"
REPORT_JSON="${OUTDIR}/report.json"

WORKDIR=""
cleanup() {
  if [[ -n "${WORKDIR}" && -d "${WORKDIR}" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

log() { echo -e "$*" | tee -a "${REPORT_TXT}" >/dev/null; }

# Find first existing file matching any of the given patterns (glob-like path fragments)
find_first() {
  local root="$1"; shift
  local pat hit
  for pat in "$@"; do
    hit="$(find "${root}" -type f -path "*${pat}*" 2>/dev/null | head -n 1 || true)"
    if [[ -n "${hit}" ]]; then
      echo "${hit}"
      return 0
    fi
  done
  return 1
}

# Normalize: bundle may nest everything under a single directory
normalize_root() {
  local r="$1"
  local top_count top_files
  top_count="$(find "${r}" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
  top_files="$(find "${r}" -maxdepth 1 -mindepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${top_count}" -eq 1 && "${top_files}" -eq 0 ]]; then
    find "${r}" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -n 1
  else
    echo "${r}"
  fi
}

# Minimal JSON escape
json_escape() {
  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g' -e 's/\r/\\r/g' -e 's/\n/\\n/g'
}

# ---------------------------
# Extract bundle if needed
# ---------------------------
if [[ -f "${INPUT}" ]]; then
  WORKDIR="$(mktemp -d -t esxi_bundle_XXXXXX)"
  tar -xzf "${INPUT}" -C "${WORKDIR}"
  ROOT="$(normalize_root "${WORKDIR}")"
elif [[ -d "${INPUT}" ]]; then
  ROOT="$(normalize_root "${INPUT}")"
else
  echo "Input not found: ${INPUT}"
  exit 1
fi

# ---------------------------
# Locate common artifacts (best-effort)
# ---------------------------

# Logs - ESXi 6.5+ uses /var/run/log, check that first
F_VMKERNEL="$(find_first "${ROOT}" "/var/run/log/vmkernel.log" "/var/log/vmkernel.log" || true)"
F_SYSLOG="$(find_first "${ROOT}" "/var/run/log/syslog.log" "/var/log/syslog.log" "syslog.log" || true)"
F_HOSTD="$(find_first "${ROOT}" "/var/run/log/hostd.log" "/var/log/hostd.log" || true)"
F_VPXA="$(find_first "${ROOT}" "/var/run/log/vpxa.log" "/var/log/vpxa.log" || true)"
F_AUTH="$(find_first "${ROOT}" "/var/run/log/auth.log" "/var/log/auth.log" || true)"
F_SHELL="$(find_first "${ROOT}" "/var/run/log/shell.log" "/var/log/shell.log" || true)"

# Config files
F_VPXA_CFG="$(find_first "${ROOT}" "/etc/vmware/vpxa/vpxa.cfg" "/etc/vmware/vpxa/dynamic.xml" "vpxa.cfg" "dynamic.xml" || true)"
F_ESXCONF="$(find_first "${ROOT}" "/etc/vmware/esx.conf" "etc/vmware/esx.conf" || true)"
F_SYSLOG_CFG="$(find_first "${ROOT}" "/etc/vmsyslog.conf" "vmsyslog.conf" || true)"

# DNS / Hostname resolution files
F_HOSTS="$(find_first "${ROOT}" "/etc/hosts" "etc/hosts" || true)"
F_RESOLV_CONF="$(find_first "${ROOT}" "/etc/resolv.conf" "etc/resolv.conf" || true)"
F_ESXCLI_DNS_SERVER="$(find_first "${ROOT}" "esxcli_network_ip_dns_server_list" "dns server list" "dns_server_list" || true)"
F_ESXCLI_DNS_SEARCH="$(find_first "${ROOT}" "esxcli_network_ip_dns_search_list" "dns search list" "dns_search_list" || true)"

# Command outputs - version/hostname
F_ESXCLI_VER="$(find_first "${ROOT}" "esxcli_system_version_get" "system_version_get" "system version get" || true)"
F_VMWARE_V="$(find_first "${ROOT}" "vmware_-vl" "vmware_-v" "vmware -v" || true)"
F_HOSTNAME_CMD="$(find_first "${ROOT}" "esxcli_system_hostname_get" "system hostname get" "hostname_get" || true)"
F_VIB_LIST="$(find_first "${ROOT}" "esxcli_software_vib_list" "software vib list" || true)"

# Command outputs - storage
F_FS_LIST="$(find_first "${ROOT}" "esxcli_storage_filesystem_list" "storage filesystem list" || true)"
F_VMFS_EXTENTS="$(find_first "${ROOT}" "esxcli_storage_vmfs_extent_list" "vmfs extent list" || true)"
F_NFS_LIST="$(find_first "${ROOT}" "esxcli_storage_nfs_list" "storage nfs list" || true)"
F_ISCSI_ADAPTERS="$(find_first "${ROOT}" "esxcli_iscsi_adapter_list" "iscsi adapter list" || true)"

# Command outputs - networking
F_VMK_NICS="$(find_first "${ROOT}" "esxcli_network_ip_interface_list" "network ip interface list" || true)"
F_PNICS="$(find_first "${ROOT}" "esxcli_network_nic_list" "network nic list" "nic_list" || true)"
F_PNIC_INFO="$(find_first "${ROOT}" "esxcli_network_nic_get" "network nic get" || true)"
F_VSWITCH="$(find_first "${ROOT}" "esxcli_network_vswitch_standard_list" "vswitch standard list" || true)"
F_DVS="$(find_first "${ROOT}" "esxcli_network_vswitch_dvs_vmware_list" "dvs vmware list" "dvswitch" || true)"
F_PORTGROUPS="$(find_first "${ROOT}" "esxcli_network_vswitch_standard_portgroup_list" "portgroup list" || true)"
F_FW_RULES="$(find_first "${ROOT}" "esxcli_network_firewall_ruleset_list" "firewall ruleset list" || true)"
F_FW_ALLOWED="$(find_first "${ROOT}" "esxcli_network_firewall_ruleset_allowedip_list" "allowedip list" || true)"

# Command outputs - syslog
F_ESXCLI_SYSLOG_CFG="$(find_first "${ROOT}" "esxcli_system_syslog_config_get" "syslog config get" "syslog_config_get" || true)"
F_ESXCLI_SYSLOG_LOGHOST="$(find_first "${ROOT}" "esxcli_system_syslog_config_loghost_get" "loghost_get" "syslog config loghost get" || true)"
F_RSYSLOG_CFG="$(find_first "${ROOT}" "/etc/rsyslog.conf" "rsyslog.conf" || true)"

# vSAN indicators - ONLY treat real vSAN cfg/logs as evidence (not .pyc files)
# Using specific paths to avoid false positives from python bytecode
F_VSAN_CFG="$(find_first "${ROOT}" "/etc/vmware/vsan/vsan.conf" "vsanperf_thumbprints.conf" "/etc/vmware/vsan/vsanhealth" || true)"
F_VSAN_LOG="$(find_first "${ROOT}" "/var/log/vsanmgmt.log" "/var/log/vsanhealth.log" "/var/log/clomd.log" "/var/log/dom.log" "/var/log/lsom.log" || true)"
F_VSAN_ESXCLI="$(find_first "${ROOT}" "esxcli_vsan_cluster" "esxcli_vsan_network" "esxcli_vsan_storage" "vsan cluster get" "vsan network list" || true)"

# ---------------------------
# Report header
# ---------------------------
log "============================================================"
log "VMware ESXi Support Bundle Triage Report"
log "Generated: $(date)"
log "Input: ${INPUT}"
log "Root: ${ROOT}"
log "============================================================"
log ""

# ---------------------------
# ESXi Host Version
# ---------------------------
ESXI_VERSION=""
ESXI_BUILD=""
ESXI_RAW=""
VERSION_SOURCE=""

# Tier 1: esxcli system version get
if [[ -n "${F_ESXCLI_VER}" && -f "${F_ESXCLI_VER}" ]]; then
  ESXI_VERSION="$(grep -E '^\s*Version:' "${F_ESXCLI_VER}" 2>/dev/null | head -n 1 | sed 's/^\s*Version:\s*//' || true)"
  ESXI_BUILD="$(grep -E '^\s*Build:' "${F_ESXCLI_VER}" 2>/dev/null | head -n 1 | sed 's/^\s*Build:\s*//' || true)"
  [[ -n "${ESXI_VERSION}" ]] && VERSION_SOURCE="${F_ESXCLI_VER}" || true
fi

# Tier 2: vmware -v output
if [[ -z "${ESXI_VERSION}" && -n "${F_VMWARE_V}" && -f "${F_VMWARE_V}" ]]; then
  ESXI_RAW="$(grep -E -m 1 'VMware ESXi|ESXi' "${F_VMWARE_V}" 2>/dev/null || true)"
  if [[ -n "${ESXI_RAW}" ]]; then
    ESXI_VERSION="$(echo "${ESXI_RAW}" | sed -nE 's/.*ESXi[[:space:]]+([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p')"
    ESXI_BUILD="$(echo "${ESXI_RAW}" | sed -nE 's/.*build-?([0-9]+).*/\1/p')"
    [[ -n "${ESXI_VERSION}" ]] && VERSION_SOURCE="${F_VMWARE_V}" || true
  fi
fi

# Tier 3: vmkernel.log fallback
if [[ -z "${ESXI_VERSION}" && -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
  ESXI_RAW="$(grep -E -m 1 'VMware ESXi|ESXi.*build' "${F_VMKERNEL}" 2>/dev/null || true)"
  if [[ -n "${ESXI_RAW}" ]]; then
    ESXI_VERSION="$(echo "${ESXI_RAW}" | sed -nE 's/.*ESXi[[:space:]]+([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p')"
    ESXI_BUILD="$(echo "${ESXI_RAW}" | sed -nE 's/.*build-?([0-9]+).*/\1/p')"
    [[ -n "${ESXI_VERSION}" ]] && VERSION_SOURCE="${F_VMKERNEL}" || true
  fi
fi

log "## ESXi Host Version"
log "- Version: ${ESXI_VERSION:-UNKNOWN}"
log "- Build:   ${ESXI_BUILD:-UNKNOWN}"
[[ -n "${VERSION_SOURCE}" ]] && log "- Source:  ${VERSION_SOURCE}" || true
log ""

# ---------------------------
# System Information (from esx.conf)
# ---------------------------
SYSTEM_UUID=""
SYSTEM_INCEPTION=""
VIB_ACCEPTANCE_LEVEL=""
MGMT_IP=""

if [[ -n "${F_ESXCONF}" && -f "${F_ESXCONF}" ]]; then
  # System UUID
  SYSTEM_UUID="$(grep -E '^/system/uuid[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"

  # Installation date
  SYSTEM_INCEPTION="$(grep -E '^/system/inception[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"

  # VIB acceptance level (security relevant)
  VIB_ACCEPTANCE_LEVEL="$(grep -E '/host-acceptance-level[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"

  # Management IP
  MGMT_IP="$(grep -E '^/adv/Misc/HostIPAddr[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
fi

log "## System Information"
log "- System UUID:        ${SYSTEM_UUID:-UNKNOWN}"
log "- Installation Date:  ${SYSTEM_INCEPTION:-UNKNOWN}"
log "- VIB Acceptance:     ${VIB_ACCEPTANCE_LEVEL:-UNKNOWN}"
log "- Management IP:      ${MGMT_IP:-UNKNOWN}"
if [[ -n "${F_ESXCONF}" ]]; then
  log "- Source:             ${F_ESXCONF}"
fi
log ""

# ---------------------------
# Hostname extraction (best-effort)
# ---------------------------
ESXI_HOSTNAME=""
ESXI_DOMAINNAME=""
HOSTNAME_SOURCES=()

# Tier 1: esxcli system hostname get
if [[ -n "${F_HOSTNAME_CMD}" && -f "${F_HOSTNAME_CMD}" ]]; then
  hn="$(grep -E '^\s*Host Name:' "${F_HOSTNAME_CMD}" 2>/dev/null | head -n 1 | sed 's/^\s*Host Name:\s*//' || true)"
  dn="$(grep -E '^\s*Domain Name:' "${F_HOSTNAME_CMD}" 2>/dev/null | head -n 1 | sed 's/^\s*Domain Name:\s*//' || true)"
  fqdn="$(grep -E 'Fully Qualified Domain Name' "${F_HOSTNAME_CMD}" 2>/dev/null | head -n 1 | sed 's/.*:\s*//' || true)"
  if [[ -n "${fqdn}" ]]; then
    ESXI_HOSTNAME="${fqdn}"
  elif [[ -n "${hn}" ]]; then
    ESXI_HOSTNAME="${hn}"
  fi
  if [[ -n "${dn}" ]]; then ESXI_DOMAINNAME="${dn}"; fi
  if [[ -n "${ESXI_HOSTNAME}" ]]; then HOSTNAME_SOURCES+=("${F_HOSTNAME_CMD}"); fi
fi

# Tier 2: esx.conf (/adv/Misc/HostName is most reliable)
if [[ -z "${ESXI_HOSTNAME}" && -n "${F_ESXCONF}" && -f "${F_ESXCONF}" ]]; then
  hn2="$(grep -E '^/adv/Misc/HostName[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
  if [[ -z "${hn2}" ]]; then
    # Fallback to other hostname patterns
    hn2="$(grep -E '(/system/hostname|/Dns/Hostname)[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
  fi
  if [[ -n "${hn2}" ]]; then
    ESXI_HOSTNAME="${hn2}"
    HOSTNAME_SOURCES+=("${F_ESXCONF}")
  fi
fi

# Tier 3: hostd.log
if [[ -z "${ESXI_HOSTNAME}" && -n "${F_HOSTD}" && -f "${F_HOSTD}" ]]; then
  hn3="$(grep -E -m 1 'hostname|HostName|FQDN' "${F_HOSTD}" 2>/dev/null | sed -nE 's/.*(hostname|HostName|FQDN)[^A-Za-z0-9\.\-]*([A-Za-z0-9\.\-]+).*/\2/p' || true)"
  if [[ -n "${hn3}" ]]; then
    ESXI_HOSTNAME="${hn3}"
    HOSTNAME_SOURCES+=("${F_HOSTD}")
  fi
fi

log "## ESXi Host Identity"
log "- Hostname/FQDN: ${ESXI_HOSTNAME:-UNKNOWN}"
[[ -n "${ESXI_DOMAINNAME}" ]] && log "- Domain Name:   ${ESXI_DOMAINNAME}" || true
if [[ "${#HOSTNAME_SOURCES[@]}" -gt 0 ]]; then
  for s in "${HOSTNAME_SOURCES[@]}"; do
    log "- Source:        ${s}"
  done
else
  log "- Source:        (no authoritative hostname artifact found)"
fi
log ""

# ---------------------------
# DNS / Name Resolution
# ---------------------------
DNS_SERVERS=()
DNS_SEARCH_DOMAINS=()
HOSTS_ENTRIES=()
DNS_SOURCES=()

# Tier 1: esxcli network ip dns server list
if [[ -n "${F_ESXCLI_DNS_SERVER}" && -f "${F_ESXCLI_DNS_SERVER}" ]]; then
  DNS_SOURCES+=("${F_ESXCLI_DNS_SERVER}")
  while IFS= read -r line; do
    # Skip header lines, extract DNS server IPs
    if [[ "${line}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      DNS_SERVERS+=("${line}")
    elif [[ "${line}" =~ DNSServers ]]; then
      # Handle "DNSServers: x.x.x.x" format
      srv="$(echo "${line}" | sed -nE 's/.*DNSServers:[[:space:]]*([0-9\.]+).*/\1/p')"
      [[ -n "${srv}" ]] && DNS_SERVERS+=("${srv}") || true
    fi
  done < "${F_ESXCLI_DNS_SERVER}"
fi

# Tier 2: resolv.conf
if [[ -n "${F_RESOLV_CONF}" && -f "${F_RESOLV_CONF}" ]]; then
  DNS_SOURCES+=("${F_RESOLV_CONF}")
  while IFS= read -r line; do
    if [[ "${line}" =~ ^nameserver ]]; then
      srv="$(echo "${line}" | awk '{print $2}')"
      [[ -n "${srv}" ]] && DNS_SERVERS+=("${srv}") || true
    elif [[ "${line}" =~ ^search ]]; then
      # Extract search domains
      domains="$(echo "${line}" | sed 's/^search[[:space:]]*//')"
      for d in ${domains}; do
        DNS_SEARCH_DOMAINS+=("${d}")
      done
    elif [[ "${line}" =~ ^domain ]]; then
      d="$(echo "${line}" | awk '{print $2}')"
      [[ -n "${d}" ]] && DNS_SEARCH_DOMAINS+=("${d}") || true
    fi
  done < "${F_RESOLV_CONF}"
fi

# Tier 3: esxcli network ip dns search list
if [[ -n "${F_ESXCLI_DNS_SEARCH}" && -f "${F_ESXCLI_DNS_SEARCH}" ]]; then
  DNS_SOURCES+=("${F_ESXCLI_DNS_SEARCH}")
  while IFS= read -r line; do
    # Skip headers, look for domain names
    if [[ "${line}" =~ ^[a-zA-Z0-9] && "${line}" =~ \. && ! "${line}" =~ ^DNS && ! "${line}" =~ ^Search ]]; then
      DNS_SEARCH_DOMAINS+=("${line}")
    elif [[ "${line}" =~ DNSSearchDomains ]]; then
      dom="$(echo "${line}" | sed -nE 's/.*DNSSearchDomains:[[:space:]]*([a-zA-Z0-9\.\-]+).*/\1/p')"
      [[ -n "${dom}" ]] && DNS_SEARCH_DOMAINS+=("${dom}") || true
    fi
  done < "${F_ESXCLI_DNS_SEARCH}"
fi

# Tier 4: esx.conf DNS settings
if [[ -n "${F_ESXCONF}" && -f "${F_ESXCONF}" ]]; then
  # Extract DNS servers from esx.conf
  esx_dns="$(grep -E '/net/pNic.*dns|/Dns/|/dns/' "${F_ESXCONF}" 2>/dev/null || true)"
  if [[ -n "${esx_dns}" ]]; then
    DNS_SOURCES+=("${F_ESXCONF} (DNS config)")
  fi
fi

# /etc/hosts parsing
if [[ -n "${F_HOSTS}" && -f "${F_HOSTS}" ]]; then
  DNS_SOURCES+=("${F_HOSTS}")
  while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "${line}" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// /}" ]] && continue
    HOSTS_ENTRIES+=("${line}")
  done < "${F_HOSTS}"
fi

log "## DNS / Name Resolution"
log ""
log "### DNS Servers"
if [[ "${#DNS_SERVERS[@]}" -gt 0 ]]; then
  # Deduplicate
  printf "%s\n" "${DNS_SERVERS[@]}" | awk '!seen[$0]++' | while read -r srv; do
    log "  - ${srv}"
  done
else
  log "  - No DNS servers found"
fi

log ""
log "### DNS Search Domains"
if [[ "${#DNS_SEARCH_DOMAINS[@]}" -gt 0 ]]; then
  printf "%s\n" "${DNS_SEARCH_DOMAINS[@]}" | awk '!seen[$0]++' | while read -r dom; do
    log "  - ${dom}"
  done
else
  log "  - No search domains found"
fi

log ""
log "### Local Host Resolution (/etc/hosts)"
if [[ "${#HOSTS_ENTRIES[@]}" -gt 0 ]]; then
  for entry in "${HOSTS_ENTRIES[@]}"; do
    log "  ${entry}"
  done
else
  log "  - /etc/hosts not found or empty"
fi

log ""
log "### resolv.conf"
if [[ -n "${F_RESOLV_CONF}" && -f "${F_RESOLV_CONF}" ]]; then
  log "- Source: ${F_RESOLV_CONF}"
  sed 's/^/  /' "${F_RESOLV_CONF}" 2>/dev/null | head -n 20 | tee -a "${REPORT_TXT}" >/dev/null || true
else
  log "  - resolv.conf not found in bundle"
fi

if [[ "${#DNS_SOURCES[@]}" -gt 0 ]]; then
  log ""
  log "### Sources"
  for s in "${DNS_SOURCES[@]}"; do
    log "  - ${s}"
  done
fi
log ""

# ---------------------------
# vCenter (VC) Management
# ---------------------------
VC_MANAGED="UNKNOWN"
VC_HOST=""
VC_IP=""
VC_EVIDENCE=()
VC_SOURCES=()

if [[ -n "${F_VPXA_CFG}" && -f "${F_VPXA_CFG}" ]]; then
  VC_MANAGED="YES"
  VC_SOURCES+=("${F_VPXA_CFG}")
  VC_CAND="$(grep -E -m 1 '<(serverIp|serverAddress|vpxdHost)>' "${F_VPXA_CFG}" 2>/dev/null \
    | sed -nE 's/.*<(serverIp|serverAddress|vpxdHost)>[[:space:]]*([^<]+)[[:space:]]*<\/.*/\2/p' || true)"
  if [[ -n "${VC_CAND}" ]]; then
    if [[ "${VC_CAND}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      VC_IP="${VC_CAND}"
    else
      VC_HOST="${VC_CAND}"
    fi
    VC_EVIDENCE+=("vCenter reference in vpxa config: ${VC_CAND}")
  else
    VC_EVIDENCE+=("vpxa config present but no serverIp/serverAddress/vpxdHost found")
  fi
elif [[ -n "${F_VPXA}" && -f "${F_VPXA}" ]]; then
  VC_MANAGED="LIKELY"
  VC_SOURCES+=("${F_VPXA}")
  VC_CAND="$(grep -E -m 1 'Connecting to|Connected to|vpxdHost|VirtualCenter|vCenter|VC' "${F_VPXA}" 2>/dev/null || true)"
  if [[ -n "${VC_CAND}" ]]; then
    VC_EVIDENCE+=("vpxa.log indicates vCenter management")
  fi
else
  VC_MANAGED="NO"
  VC_EVIDENCE+=("No vpxa.cfg/dynamic.xml or vpxa.log found; host appears standalone")
fi

log "## vCenter (VC) Management"
log "- Managed by vCenter: ${VC_MANAGED}"
log "- vCenter Hostname:   ${VC_HOST:-UNKNOWN}"
log "- vCenter IP:         ${VC_IP:-UNKNOWN}"
if [[ "${#VC_SOURCES[@]}" -gt 0 ]]; then
  for s in "${VC_SOURCES[@]}"; do
    log "- Source:            ${s}"
  done
fi
if [[ "${#VC_EVIDENCE[@]}" -gt 0 ]]; then
  for e in "${VC_EVIDENCE[@]}"; do
    log "  - Evidence: ${e}"
  done
fi
log ""

# ---------------------------
# vSAN Detection
# ---------------------------
VSAN_PRESENT="UNKNOWN"
VSAN_EVIDENCE=()
VSAN_SOURCES=()

# Tier 1: vsan.conf or vsanperf_thumbprints.conf -> YES
if [[ -n "${F_VSAN_CFG}" && -e "${F_VSAN_CFG}" ]]; then
  # Exclude false positives from .pyc files
  if [[ ! "${F_VSAN_CFG}" =~ \.pyc$ ]]; then
    VSAN_PRESENT="YES"
    VSAN_EVIDENCE+=("vSAN config present")
    VSAN_SOURCES+=("${F_VSAN_CFG}")
  fi
fi

# Tier 2: vsanmgmt.log, clomd.log -> LIKELY
if [[ -n "${F_VSAN_LOG}" && -f "${F_VSAN_LOG}" ]]; then
  # Exclude false positives from .pyc files
  if [[ ! "${F_VSAN_LOG}" =~ \.pyc$ ]]; then
    [[ "${VSAN_PRESENT}" == "UNKNOWN" ]] && VSAN_PRESENT="LIKELY" || true
    VSAN_EVIDENCE+=("vSAN-related log present")
    VSAN_SOURCES+=("${F_VSAN_LOG}")
  fi
fi

# Tier 3: esxcli vsan output -> LIKELY
if [[ -n "${F_VSAN_ESXCLI}" && -f "${F_VSAN_ESXCLI}" ]]; then
  [[ "${VSAN_PRESENT}" == "UNKNOWN" ]] && VSAN_PRESENT="LIKELY" || true
  VSAN_EVIDENCE+=("vSAN esxcli output present")
  VSAN_SOURCES+=("${F_VSAN_ESXCLI}")
fi

# Tier 4: vmkernel.log grep for vsan|clomd|dom|lsom -> POSSIBLE
if [[ "${VSAN_PRESENT}" == "UNKNOWN" ]]; then
  if [[ -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
    # Look for real vSAN indicators, excluding generic matches
    if grep -Eq '\bvsan\b|\bclomd\b|\blsom\b' "${F_VMKERNEL}" 2>/dev/null; then
      VSAN_PRESENT="POSSIBLE"
      VSAN_EVIDENCE+=("vSAN strings in vmkernel.log")
      VSAN_SOURCES+=("${F_VMKERNEL}")
    else
      VSAN_PRESENT="NO_EVIDENCE"
    fi
  else
    VSAN_PRESENT="NO_EVIDENCE"
  fi
fi

log "## vSAN"
log "- vSAN indicated: ${VSAN_PRESENT}"
if [[ "${#VSAN_SOURCES[@]}" -gt 0 ]]; then
  for s in "${VSAN_SOURCES[@]}"; do
    log "- Source:        ${s}"
  done
fi
if [[ "${#VSAN_EVIDENCE[@]}" -gt 0 ]]; then
  for e in "${VSAN_EVIDENCE[@]}"; do
    log "  - Evidence: ${e}"
  done
fi
log ""

# ---------------------------
# Datastores / Storage (with actual content extraction)
# ---------------------------
log "## Datastores / Storage"
if [[ -n "${F_FS_LIST}" && -f "${F_FS_LIST}" ]]; then
  log "- Source: ${F_FS_LIST}"
  log "  (filesystem list excerpt)"
  grep -E 'Mount Point|Volume Name|UUID|Type|Mounted|VMFS|NFS|vfat|vvol|vsan' "${F_FS_LIST}" 2>/dev/null \
    | head -n 120 | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
else
  log "- No filesystem list command output found."
fi

if [[ -n "${F_VMFS_EXTENTS}" && -f "${F_VMFS_EXTENTS}" ]]; then
  log ""
  log "- VMFS Extents Source: ${F_VMFS_EXTENTS}"
  head -n 120 "${F_VMFS_EXTENTS}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
fi

if [[ -n "${F_NFS_LIST}" && -f "${F_NFS_LIST}" ]]; then
  log ""
  log "- NFS Source: ${F_NFS_LIST}"
  head -n 120 "${F_NFS_LIST}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
fi

if [[ -n "${F_ISCSI_ADAPTERS}" && -f "${F_ISCSI_ADAPTERS}" ]]; then
  log ""
  log "- iSCSI Adapters Source: ${F_ISCSI_ADAPTERS}"
  head -n 120 "${F_ISCSI_ADAPTERS}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
fi
log ""

# ---------------------------
# Networking (with actual content extraction)
# ---------------------------
log "## Networking"

# Physical NICs (pNICs) - vmnic0, vmnic1, etc.
log "### Physical NICs (pNICs)"
PNIC_DATA_FOUND=false
if [[ -n "${F_PNICS}" && -f "${F_PNICS}" ]]; then
  log "- Source: ${F_PNICS}"
  head -n 100 "${F_PNICS}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
  PNIC_DATA_FOUND=true
fi

# Fallback/supplement: Extract pNIC info from esx.conf
if [[ -n "${F_ESXCONF}" && -f "${F_ESXCONF}" ]]; then
  ESXCONF_PNICS="$(grep -E '^/net/pnic/child\[[0-9]+\]/(name|mac|nicEnabled)[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 60 || true)"
  if [[ -n "${ESXCONF_PNICS}" ]]; then
    if [[ "${PNIC_DATA_FOUND}" == "false" ]]; then
      log "- Source: ${F_ESXCONF} (esx.conf)"
    else
      log ""
      log "- Additional from esx.conf:"
    fi
    # Parse and display in a cleaner format
    log "  pNIC Summary from esx.conf:"
    grep -E '^/net/pnic/child\[[0-9]+\]/name[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | while read -r line; do
      nic_idx="$(echo "${line}" | sed -nE 's|.*/child\[([0-9]+)\]/.*|\1|p')"
      nic_name="$(echo "${line}" | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p')"
      nic_mac="$(grep -E "^/net/pnic/child\[${nic_idx}\]/mac[[:space:]]*=" "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
      nic_enabled="$(grep -E "^/net/pnic/child\[${nic_idx}\]/nicEnabled[[:space:]]*=" "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
      log "    ${nic_name}: MAC=${nic_mac:-unknown} Enabled=${nic_enabled:-unknown}"
    done
    PNIC_DATA_FOUND=true
  fi
fi

if [[ "${PNIC_DATA_FOUND}" == "false" ]]; then
  log "- No physical NIC information found."
fi
log ""

# VMkernel NICs (vmk0, vmk1, etc.)
log "### VMkernel NICs (vmk)"
VMK_DATA_FOUND=false
if [[ -n "${F_VMK_NICS}" && -f "${F_VMK_NICS}" ]]; then
  log "- Source: ${F_VMK_NICS}"
  head -n 160 "${F_VMK_NICS}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
  VMK_DATA_FOUND=true
fi

# Fallback/supplement: Extract vmk info from esx.conf
if [[ -n "${F_ESXCONF}" && -f "${F_ESXCONF}" ]]; then
  ESXCONF_VMKS="$(grep -E '^/net/vmkernelnic/child\[[0-9]+\]/(name|ipv4address|ipv4netmask|mac|portgroup)[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 60 || true)"
  if [[ -n "${ESXCONF_VMKS}" ]]; then
    if [[ "${VMK_DATA_FOUND}" == "false" ]]; then
      log "- Source: ${F_ESXCONF} (esx.conf)"
    else
      log ""
      log "- Additional from esx.conf:"
    fi
    log "  VMkernel NIC Summary from esx.conf:"
    grep -E '^/net/vmkernelnic/child\[[0-9]+\]/name[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | while read -r line; do
      vmk_idx="$(echo "${line}" | sed -nE 's|.*/child\[([0-9]+)\]/.*|\1|p')"
      vmk_name="$(echo "${line}" | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p')"
      vmk_ip="$(grep -E "^/net/vmkernelnic/child\[${vmk_idx}\]/ipv4address[[:space:]]*=" "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
      vmk_mask="$(grep -E "^/net/vmkernelnic/child\[${vmk_idx}\]/ipv4netmask[[:space:]]*=" "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
      vmk_pg="$(grep -E "^/net/vmkernelnic/child\[${vmk_idx}\]/portgroup[[:space:]]*=" "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
      log "    ${vmk_name}: IP=${vmk_ip:-unknown}/${vmk_mask:-unknown} PortGroup=${vmk_pg:-unknown}"
    done
    VMK_DATA_FOUND=true
  fi
fi

if [[ "${VMK_DATA_FOUND}" == "false" ]]; then
  log "- No VMkernel NIC information found."
fi
log ""

# vSwitches
log "### vSwitches"
if [[ -n "${F_VSWITCH}" && -f "${F_VSWITCH}" ]]; then
  log "- Standard vSwitches Source: ${F_VSWITCH}"
  head -n 200 "${F_VSWITCH}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
elif [[ -n "${F_ESXCONF}" && -f "${F_ESXCONF}" ]]; then
  # Extract vSwitch info from esx.conf
  ESXCONF_VSWITCHES="$(grep -E '^/net/vswitch/child\[[0-9]+\]/name[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null || true)"
  if [[ -n "${ESXCONF_VSWITCHES}" ]]; then
    log "- Source: ${F_ESXCONF} (esx.conf)"
    log "  vSwitch Summary from esx.conf:"
    echo "${ESXCONF_VSWITCHES}" | while read -r line; do
      vs_idx="$(echo "${line}" | sed -nE 's|.*/child\[([0-9]+)\]/.*|\1|p')"
      vs_name="$(echo "${line}" | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p')"
      vs_uplink="$(grep -E "^/net/vswitch/child\[${vs_idx}\]/uplinks/child\[0000\]/pnic[[:space:]]*=" "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
      log "    ${vs_name}: Uplink=${vs_uplink:-none}"
      # List port groups for this vSwitch
      grep -E "^/net/vswitch/child\[${vs_idx}\]/portgroup/child\[[0-9]+\]/name[[:space:]]*=" "${F_ESXCONF}" 2>/dev/null | while read -r pgline; do
        pg_name="$(echo "${pgline}" | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p')"
        pg_idx="$(echo "${pgline}" | sed -nE 's|.*/portgroup/child\[([0-9]+)\]/.*|\1|p')"
        pg_vlan="$(grep -E "^/net/vswitch/child\[${vs_idx}\]/portgroup/child\[${pg_idx}\]/vlanId[[:space:]]*=" "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
        log "      - PortGroup: ${pg_name} (VLAN ${pg_vlan:-0})"
      done
    done
  else
    log "- No vSwitch information found."
  fi
else
  log "- No vSwitch information found."
fi

if [[ -n "${F_DVS}" && -f "${F_DVS}" ]]; then
  log ""
  log "- Distributed vSwitches Source: ${F_DVS}"
  head -n 100 "${F_DVS}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
fi
log ""

# Port Groups (from esxcli if available)
if [[ -n "${F_PORTGROUPS}" && -f "${F_PORTGROUPS}" ]]; then
  log "### Port Groups"
  log "- Source: ${F_PORTGROUPS}"
  head -n 200 "${F_PORTGROUPS}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
  log ""
fi

# Firewall
log "### Firewall"
if [[ -n "${F_FW_RULES}" && -f "${F_FW_RULES}" ]]; then
  log "- Firewall Rulesets Source: ${F_FW_RULES}"
  head -n 200 "${F_FW_RULES}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
fi

if [[ -n "${F_FW_ALLOWED}" && -f "${F_FW_ALLOWED}" ]]; then
  log ""
  log "- Firewall Allowed IPs Source: ${F_FW_ALLOWED}"
  head -n 200 "${F_FW_ALLOWED}" 2>/dev/null | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
fi
log ""

# ---------------------------
# Connected / Installed Products (VIB + log keyword scanning)
# ---------------------------
log "## Connected / Installed Products (Best-Effort)"
PRODUCT_HITS=()

if [[ -n "${F_VIB_LIST}" && -f "${F_VIB_LIST}" ]]; then
  log "- VIB list source: ${F_VIB_LIST}"
  # Look for common product/VIB indicators
  if grep -Eqi 'nsx|vsip|vdr|vshield|vxlan' "${F_VIB_LIST}" 2>/dev/null; then PRODUCT_HITS+=("NSX (VIB indicator)"); fi
  if grep -Eqi 'vsan|clomd|lsom|dom' "${F_VIB_LIST}" 2>/dev/null; then PRODUCT_HITS+=("vSAN (VIB indicator)"); fi
  if grep -Eqi 'hbr|vSphere Replication|vr-' "${F_VIB_LIST}" 2>/dev/null; then PRODUCT_HITS+=("vSphere Replication (VIB indicator)"); fi
  if grep -Eqi 'veeam|rubrik|commvault|cohesity|datto' "${F_VIB_LIST}" 2>/dev/null; then PRODUCT_HITS+=("Backup agent VIBs (possible)"); fi
  if grep -Eqi 'dell|idrac|openmanage|hp|hpe|ilo|nimble|pure' "${F_VIB_LIST}" 2>/dev/null; then PRODUCT_HITS+=("Hardware/CIM vendor VIBs"); fi
else
  log "- No VIB list output found."
fi

# Add keyword-based checks from logs
for f in "${F_HOSTD:-}" "${F_VPXA:-}" "${F_VMKERNEL:-}"; do
  [[ -f "${f}" ]] || continue
  if grep -Eqi 'nsx|vshield|vxlan|vsip' "${f}" 2>/dev/null; then PRODUCT_HITS+=("NSX (log indicator: $(basename "${f}"))"); fi
  if grep -Eqi 'hbr|replication|vrms|vSphere Replication' "${f}" 2>/dev/null; then PRODUCT_HITS+=("vSphere Replication (log indicator: $(basename "${f}"))"); fi
  if grep -Eqi 'backup|veeam|rubrik|commvault|cohesity' "${f}" 2>/dev/null; then PRODUCT_HITS+=("Backup tooling (log indicator: $(basename "${f}"))"); fi
done

# Deduplicate and output
if [[ "${#PRODUCT_HITS[@]}" -gt 0 ]]; then
  printf "%s\n" "${PRODUCT_HITS[@]}" | awk '!seen[$0]++' | sed 's/^/- /' | tee -a "${REPORT_TXT}" >/dev/null
else
  log "- No strong indicators found (or VIB/log outputs not present in bundle)."
fi
log ""

# ---------------------------
# Log Locations (in this bundle)
# ---------------------------
LOG_DIR_VARLOG="$(find "${ROOT}" -type d -path "*/var/log" 2>/dev/null | head -n 1 || true)"
LOG_DIR_VARRUNLOG="$(find "${ROOT}" -type d -path "*/var/run/log" 2>/dev/null | head -n 1 || true)"

log "## Log Locations (in this bundle)"
[[ -n "${LOG_DIR_VARLOG}" ]] && log "- /var/log:     ${LOG_DIR_VARLOG}" || true
[[ -n "${LOG_DIR_VARRUNLOG}" ]] && log "- /var/run/log: ${LOG_DIR_VARRUNLOG}" || true
log "- Notable log files found:"
[[ -n "${F_VMKERNEL}" ]] && log "  - vmkernel: ${F_VMKERNEL}" || true
[[ -n "${F_SYSLOG}"  ]] && log "  - syslog:   ${F_SYSLOG}" || true
[[ -n "${F_HOSTD}"   ]] && log "  - hostd:    ${F_HOSTD}" || true
[[ -n "${F_VPXA}"    ]] && log "  - vpxa:     ${F_VPXA}" || true
[[ -n "${F_AUTH}"    ]] && log "  - auth:     ${F_AUTH}" || true
[[ -n "${F_SHELL}"   ]] && log "  - shell:    ${F_SHELL}" || true

log ""

# ============================================================
# SECURITY FORENSICS ANALYSIS
# ============================================================
log "## Security Forensics Analysis"
log ""

# Initialize security tracking variables
SEC_RANSOMWARE_CONFIDENCE="NONE"
SEC_RANSOMWARE_EVIDENCE=()
SEC_RANSOMWARE_ENCRYPTED_FILES=()
SEC_RANSOMWARE_RANSOM_NOTES=()
SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS=()

SEC_VMESCAPE_CONFIDENCE="NONE"
SEC_VMESCAPE_EVIDENCE=()
SEC_VMESCAPE_CVE_INDICATORS=()

SEC_PERSISTENCE_EVIDENCE=()
SEC_PERSISTENCE_STARTUP_SCRIPTS=()
SEC_PERSISTENCE_MALICIOUS_VIBS=()

SEC_CONFIG_FINDINGS=()

# ---------------------------
# Section 0: Security Configuration Analysis (from esx.conf)
# ---------------------------
if [[ -n "${F_ESXCONF}" && -f "${F_ESXCONF}" ]]; then
  # SSH configuration
  SSH_ENABLED="$(grep -E '^/firewall/services/sshServer/enabled[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
  SSH_ALLOWEDALL="$(grep -E '^/firewall/services/sshServer/allowedall[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
  SSH_ALLOWED_IPS="$(grep -E '^/firewall/services/sshServer/allowedip\[' "${F_ESXCONF}" 2>/dev/null | sed -nE 's/.*ipstr[[:space:]]*=[[:space:]]*"(.*)".*/\1/p' || true)"

  if [[ "${SSH_ENABLED}" == "true" ]]; then
    if [[ "${SSH_ALLOWEDALL}" == "true" ]]; then
      SEC_CONFIG_FINDINGS+=("[WARNING] SSH enabled and open to ALL IPs")
    else
      SEC_CONFIG_FINDINGS+=("[INFO] SSH enabled with IP restrictions")
      if [[ -n "${SSH_ALLOWED_IPS}" ]]; then
        while IFS= read -r ip; do
          SEC_CONFIG_FINDINGS+=("[INFO]   - Allowed: ${ip}")
        done <<< "${SSH_ALLOWED_IPS}"
      fi
    fi
  else
    SEC_CONFIG_FINDINGS+=("[OK] SSH disabled")
  fi

  # SLP (CIMSLP) status - CVE-2020-3992 relevant
  SLP_ENABLED="$(grep -E '^/firewall/services/CIMSLP/enabled[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
  if [[ "${SLP_ENABLED}" == "true" ]]; then
    SEC_CONFIG_FINDINGS+=("[WARNING] OpenSLP (CIMSLP) is ENABLED - vulnerable to CVE-2020-3992")
    SEC_VMESCAPE_EVIDENCE+=("[CONFIG] OpenSLP enabled in esx.conf firewall")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="LOW"
    fi
  else
    SEC_CONFIG_FINDINGS+=("[OK] OpenSLP (CIMSLP) disabled")
  fi

  # Shell timeout settings
  SHELL_TIMEOUT="$(grep -E '^/adv/UserVars/ESXiShellInteractiveTimeOut[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
  if [[ -n "${SHELL_TIMEOUT}" ]]; then
    if [[ "${SHELL_TIMEOUT}" == "0" ]]; then
      SEC_CONFIG_FINDINGS+=("[WARNING] Shell interactive timeout disabled (0)")
    else
      SEC_CONFIG_FINDINGS+=("[INFO] Shell interactive timeout: ${SHELL_TIMEOUT}s")
    fi
  fi

  # Suppressed warnings (security concern)
  SUPPRESS_SHELL="$(grep -E '^/adv/UserVars/SuppressShellWarning[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
  if [[ "${SUPPRESS_SHELL}" == "1" ]]; then
    SEC_CONFIG_FINDINGS+=("[WARNING] Shell access warning suppressed")
  fi

  SUPPRESS_HT="$(grep -E '^/adv/UserVars/SuppressHyperthreadWarning[[:space:]]*=' "${F_ESXCONF}" 2>/dev/null | head -n 1 | sed -nE 's/.*=[[:space:]]*"(.*)".*/\1/p' || true)"
  if [[ "${SUPPRESS_HT}" == "1" ]]; then
    SEC_CONFIG_FINDINGS+=("[INFO] Hyperthreading warning suppressed")
  fi

  # VIB acceptance level check (security)
  if [[ "${VIB_ACCEPTANCE_LEVEL}" == "community" ]]; then
    SEC_CONFIG_FINDINGS+=("[WARNING] VIB acceptance level is 'community' - allows unsigned VIBs")
  elif [[ "${VIB_ACCEPTANCE_LEVEL}" == "partner" ]]; then
    SEC_CONFIG_FINDINGS+=("[INFO] VIB acceptance level is 'partner'")
  elif [[ "${VIB_ACCEPTANCE_LEVEL}" == "vmware_certified" || "${VIB_ACCEPTANCE_LEVEL}" == "vmwarecertified" ]]; then
    SEC_CONFIG_FINDINGS+=("[OK] VIB acceptance level is 'vmware_certified'")
  fi
fi

log "### Security Configuration (from esx.conf)"
if [[ "${#SEC_CONFIG_FINDINGS[@]}" -gt 0 ]]; then
  for finding in "${SEC_CONFIG_FINDINGS[@]}"; do
    log "  ${finding}"
  done
else
  log "  - No esx.conf available for security configuration analysis"
fi
log ""

# ---------------------------
# Section 1: Enhanced Ransomware Detection
# ---------------------------

# 1.1 Extended ransomware file extensions
RANSOMWARE_EXTENSIONS="-name *.babyk -o -name *.royal -o -name *.blackbasta -o -name *.esxiargs -o -name *.akira -o -name *.blackcat -o -name *.alphv -o -name *.encrypted -o -name *.locked -o -name *.crypted -o -name *.enc -o -name *.crypt -o -name *.siege"

ENCRYPTED_FILES="$(find "${ROOT}" -type f \( ${RANSOMWARE_EXTENSIONS} \) 2>/dev/null | head -n 50 || true)"
if [[ -n "${ENCRYPTED_FILES}" ]]; then
  while IFS= read -r f; do
    SEC_RANSOMWARE_ENCRYPTED_FILES+=("${f}")
  done <<< "${ENCRYPTED_FILES}"
  SEC_RANSOMWARE_EVIDENCE+=("[ENCRYPTED_FILES] Found files with ransomware extensions")
  SEC_RANSOMWARE_CONFIDENCE="HIGH"
fi

# 1.2 Ransom note detection
RANSOM_NOTES="$(find "${ROOT}" -type f \( \
  -iname "HOW_TO_RESTORE*.txt" -o \
  -iname "HOW_TO_DECRYPT*.txt" -o \
  -iname "README_TO_RESTORE*.txt" -o \
  -iname "RECOVER*.txt" -o \
  -iname "DECRYPT*.txt" -o \
  -iname "!README!.txt" -o \
  -iname "ransom*.txt" -o \
  -iname "restore_files*.txt" -o \
  -iname "*_readme.txt" -o \
  -iname "unlock*.txt" \
  \) 2>/dev/null | head -n 20 || true)"

if [[ -n "${RANSOM_NOTES}" ]]; then
  while IFS= read -r f; do
    SEC_RANSOMWARE_RANSOM_NOTES+=("${f}")
  done <<< "${RANSOM_NOTES}"
  SEC_RANSOMWARE_EVIDENCE+=("[RANSOM_NOTE] Found potential ransom note files")
  if [[ "${SEC_RANSOMWARE_CONFIDENCE}" != "HIGH" ]]; then
    SEC_RANSOMWARE_CONFIDENCE="HIGH"
  fi
fi

# 1.3 Suspicious scripts in /tmp and /scratch
SUSPICIOUS_SCRIPT_PATTERNS="encrypt.sh|ksmd|autobackup.bin|update.sh|tools.sh"
TMP_SCRIPTS="$(find "${ROOT}" -type f \( -path "*/tmp/*" -o -path "*/scratch/*" \) \( -name "*.sh" -o -name "ksmd" -o -name "tools" -o -name "update" -o -name "autobackup.bin" \) 2>/dev/null | head -n 20 || true)"

if [[ -n "${TMP_SCRIPTS}" ]]; then
  while IFS= read -r f; do
    SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS+=("${f}")
  done <<< "${TMP_SCRIPTS}"
  SEC_RANSOMWARE_EVIDENCE+=("[SUSPICIOUS_SCRIPT] Scripts found in /tmp or /scratch")
  if [[ "${SEC_RANSOMWARE_CONFIDENCE}" == "NONE" ]]; then
    SEC_RANSOMWARE_CONFIDENCE="MEDIUM"
  fi
fi

# Check for ELF binaries in unusual locations
ELF_IN_TMP="$(find "${ROOT}" -type f \( -path "*/tmp/*" -o -path "*/scratch/*" \) -exec sh -c 'file "$1" 2>/dev/null | grep -q "ELF" && echo "$1"' _ {} \; 2>/dev/null | head -n 10 || true)"
if [[ -n "${ELF_IN_TMP}" ]]; then
  while IFS= read -r f; do
    SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS+=("${f}")
  done <<< "${ELF_IN_TMP}"
  SEC_RANSOMWARE_EVIDENCE+=("[ELF_BINARY] ELF binaries found in /tmp or /scratch")
  if [[ "${SEC_RANSOMWARE_CONFIDENCE}" == "NONE" ]]; then
    SEC_RANSOMWARE_CONFIDENCE="MEDIUM"
  fi
fi

# 1.4 Modified startup scripts in /etc/rc.local.d/
F_RC_LOCAL_D="$(find "${ROOT}" -type d -path "*/etc/rc.local.d" 2>/dev/null | head -n 1 || true)"
if [[ -n "${F_RC_LOCAL_D}" && -d "${F_RC_LOCAL_D}" ]]; then
  # Check for non-standard scripts (anything other than local.sh)
  NON_STANDARD_STARTUP="$(find "${F_RC_LOCAL_D}" -type f -name "*.sh" ! -name "local.sh" 2>/dev/null || true)"
  if [[ -n "${NON_STANDARD_STARTUP}" ]]; then
    while IFS= read -r f; do
      # Check if this is a known malicious VIB indicator
      if [[ "$(basename "${f}")" == "vmware_local.sh" ]]; then
        SEC_RANSOMWARE_EVIDENCE+=("[MALICIOUS_VIB] vmware_local.sh found - known malicious VIB indicator")
        SEC_RANSOMWARE_CONFIDENCE="HIGH"
      fi
      SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS+=("${f}")
    done <<< "${NON_STANDARD_STARTUP}"
    SEC_RANSOMWARE_EVIDENCE+=("[STARTUP_SCRIPT] Non-standard scripts in rc.local.d")
    if [[ "${SEC_RANSOMWARE_CONFIDENCE}" == "NONE" ]]; then
      SEC_RANSOMWARE_CONFIDENCE="LOW"
    fi
  fi
fi

# ---------------------------
# Section 2: VM Escape Vulnerability Detection
# ---------------------------

# Helper function to check log for patterns and track evidence
check_log_patterns() {
  local logfile="$1"
  local pattern="$2"
  local cve_id="$3"
  local confidence="$4"
  local description="$5"

  if [[ -n "${logfile}" && -f "${logfile}" ]]; then
    local matches
    matches="$(grep -Eni "${pattern}" "${logfile}" 2>/dev/null | head -n 5 || true)"
    if [[ -n "${matches}" ]]; then
      local first_match
      first_match="$(echo "${matches}" | head -n 1)"
      SEC_VMESCAPE_CVE_INDICATORS+=("[${cve_id}] ${description} (${logfile}:${first_match%%:*})")
      SEC_VMESCAPE_EVIDENCE+=("[${confidence}] ${cve_id}: ${description}")
      return 0
    fi
  fi
  return 1
}

# 2.1 OpenSLP Detection (CVE-2020-3992, CVE-2019-5544)
if [[ -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
  SLP_HITS="$(grep -Eni 'slp|slpd|port.427|openslp' "${F_VMKERNEL}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${SLP_HITS}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CVE-2020-3992/CVE-2019-5544] OpenSLP activity in vmkernel.log")
    SEC_VMESCAPE_EVIDENCE+=("[HIGH] CVE-2020-3992: OpenSLP indicators detected")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="HIGH"
    fi
  fi
fi

# Check firewall for port 427 exposure
if [[ -n "${F_FW_RULES}" && -f "${F_FW_RULES}" ]]; then
  SLP_FW="$(grep -E '427|slp' "${F_FW_RULES}" 2>/dev/null | grep -Ei 'true|enabled' || true)"
  if [[ -n "${SLP_FW}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CVE-2020-3992] Port 427 (SLP) enabled in firewall")
    SEC_VMESCAPE_EVIDENCE+=("[MEDIUM] OpenSLP port 427 exposed in firewall rules")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="MEDIUM"
    fi
  fi
fi

# 2.2 VMCI/vSock vulnerabilities (CVE-2022-31696 and related)
if [[ -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
  VMCI_HITS="$(grep -Eni 'vmci.*error|vsock.*error|heap.overflow|memory.corruption' "${F_VMKERNEL}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${VMCI_HITS}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CVE-2022-31696] VMCI/vSock anomalies in vmkernel.log")
    SEC_VMESCAPE_EVIDENCE+=("[HIGH] CVE-2022-31696: VMCI/vSock memory corruption indicators")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" != "CRITICAL" ]]; then
      SEC_VMESCAPE_CONFIDENCE="HIGH"
    fi
  fi
fi

# 2.3 CD-ROM overflow (CVE-2021-22045)
if [[ -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
  CDROM_HITS="$(grep -Eni 'cdrom.*error|cd-rom.*overflow|ide.*overflow' "${F_VMKERNEL}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${CDROM_HITS}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CVE-2021-22045] CD-ROM related errors in vmkernel.log")
    SEC_VMESCAPE_EVIDENCE+=("[MEDIUM] CVE-2021-22045: CD-ROM overflow indicators")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="MEDIUM"
    fi
  fi
fi

# 2.4 execInstalledOnly violation - CRITICAL indicator
if [[ -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
  EXEC_VIOLATION="$(grep -Eni 'execInstalledOnly.*violation|unsigned.*execution' "${F_VMKERNEL}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${EXEC_VIOLATION}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CRITICAL] execInstalledOnly violation detected")
    SEC_VMESCAPE_EVIDENCE+=("[CRITICAL] Unsigned code execution attempted")
    SEC_VMESCAPE_CONFIDENCE="CRITICAL"
  fi
fi

# 2.5 General memory corruption indicators
if [[ -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
  MEM_HITS="$(grep -Eni 'HEAP.*CORRUPT|OVERFLOW.*DETECT|EXCEPTION.*FAULT|purple.*screen|psod' "${F_VMKERNEL}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${MEM_HITS}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[MEMORY] Memory corruption/exception indicators")
    SEC_VMESCAPE_EVIDENCE+=("[MEDIUM] Memory corruption indicators in vmkernel.log")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="MEDIUM"
    fi
  fi
fi

# 2.5.1 USB UHCI/XHCI controller vulnerabilities (CVE-2024-22252, CVE-2024-22253, CVE-2024-22254)
# These affect ESXi 7.x and 8.x
if [[ -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
  USB_HITS="$(grep -Eni 'uhci.*error|xhci.*error|usb.*overflow|usb.*corrupt|vmx.*usb.*exception' "${F_VMKERNEL}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${USB_HITS}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CVE-2024-22252/22253/22254] USB controller anomalies detected")
    SEC_VMESCAPE_EVIDENCE+=("[HIGH] CVE-2024-22252: USB UHCI/XHCI controller exploitation indicators")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" != "CRITICAL" ]]; then
      SEC_VMESCAPE_CONFIDENCE="HIGH"
    fi
  fi
fi

# 2.5.2 Sandbox escape indicators (ESXi 8.x specific)
if [[ -n "${F_VMKERNEL}" && -f "${F_VMKERNEL}" ]]; then
  SANDBOX_HITS="$(grep -Eni 'sandbox.*escape|vmx.*sandbox|sandboxed.*process.*exit' "${F_VMKERNEL}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${SANDBOX_HITS}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[SANDBOX] VMX sandbox escape indicators detected")
    SEC_VMESCAPE_EVIDENCE+=("[CRITICAL] Sandbox escape activity detected")
    SEC_VMESCAPE_CONFIDENCE="CRITICAL"
  fi
fi

# 2.6 hostd.log patterns - Malicious VIB installation
if [[ -n "${F_HOSTD}" && -f "${F_HOSTD}" ]]; then
  VIB_INSTALL="$(grep -Eni 'VIB.*install|package.*added|esxcli.*software.*vib' "${F_HOSTD}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${VIB_INSTALL}" ]]; then
    SEC_VMESCAPE_EVIDENCE+=("[MEDIUM] VIB installation activity detected in hostd.log")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="LOW"
    fi
  fi

  # Guest operations abuse (CVE-2023-20867)
  GUEST_OPS="$(grep -Eni 'Guest.*Operation.*Failed|GuestOperation|vmtoolsd.*error' "${F_HOSTD}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${GUEST_OPS}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CVE-2023-20867] Guest operations anomalies in hostd.log")
    SEC_VMESCAPE_EVIDENCE+=("[MEDIUM] CVE-2023-20867: Guest operations abuse indicators")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="MEDIUM"
    fi
  fi
fi

# 2.7 vpxa.log - pyvmomi user-agent (UNC3886 indicator)
if [[ -n "${F_VPXA}" && -f "${F_VPXA}" ]]; then
  PYVMOMI="$(grep -Eni 'pyvmomi|Python.*Linux|python.*vmware' "${F_VPXA}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${PYVMOMI}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[UNC3886] pyvmomi/Python user-agent detected in vpxa.log")
    SEC_VMESCAPE_EVIDENCE+=("[MEDIUM] UNC3886: pyvmomi automation detected (APT indicator)")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="MEDIUM"
    fi
  fi
fi

# 2.8 AD Authentication Bypass (CVE-2024-37085)
if [[ -n "${F_AUTH}" && -f "${F_AUTH}" ]]; then
  AD_BYPASS="$(grep -Eni 'ESX.Admins|esx.*admin.*group|domain.*admin|AD.*group.*added' "${F_AUTH}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${AD_BYPASS}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CVE-2024-37085] AD group manipulation in auth.log")
    SEC_VMESCAPE_EVIDENCE+=("[CRITICAL] CVE-2024-37085: AD authentication bypass indicators")
    SEC_VMESCAPE_CONFIDENCE="CRITICAL"
  fi
fi

# Check esx.conf for AD configuration changes
if [[ -n "${F_ESXCONF}" && -f "${F_ESXCONF}" ]]; then
  AD_CONFIG="$(grep -Eni 'ActiveDirectory|LDAP|domain.*join|ESX.*Admins' "${F_ESXCONF}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${AD_CONFIG}" ]]; then
    SEC_VMESCAPE_CVE_INDICATORS+=("[CVE-2024-37085] AD configuration present in esx.conf")
    SEC_VMESCAPE_EVIDENCE+=("[LOW] AD integration configured - verify group membership")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="LOW"
    fi
  fi
fi

# 2.9 auth.log - Brute force / authentication anomalies
if [[ -n "${F_AUTH}" && -f "${F_AUTH}" ]]; then
  BRUTE_FORCE="$(grep -ciE 'Failed|failure|invalid' "${F_AUTH}" 2>/dev/null | head -n 1 | tr -d '[:space:]' || echo 0)"
  # Ensure we have a valid number
  if [[ "${BRUTE_FORCE}" =~ ^[0-9]+$ ]] && [[ "${BRUTE_FORCE}" -gt 50 ]]; then
    SEC_VMESCAPE_EVIDENCE+=("[MEDIUM] High count of authentication failures (${BRUTE_FORCE})")
    if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
      SEC_VMESCAPE_CONFIDENCE="LOW"
    fi
  fi
fi

# 2.10 shell.log - Persistence indicators
if [[ -n "${F_SHELL}" && -f "${F_SHELL}" ]]; then
  SHELL_ABUSE="$(grep -Eni 'ESXShell.*enable|SSH.*enable|TSM.*enable' "${F_SHELL}" 2>/dev/null | head -n 10 || true)"
  if [[ -n "${SHELL_ABUSE}" ]]; then
    # Check for suspicious commands following shell enablement
    SUSPICIOUS_CMDS="$(grep -Eni 'wget|curl|chmod|/tmp/|python|perl|nc|netcat|base64' "${F_SHELL}" 2>/dev/null | head -n 5 || true)"
    if [[ -n "${SUSPICIOUS_CMDS}" ]]; then
      SEC_VMESCAPE_EVIDENCE+=("[MEDIUM] Suspicious commands in shell.log following shell enablement")
      if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" || "${SEC_VMESCAPE_CONFIDENCE}" == "LOW" ]]; then
        SEC_VMESCAPE_CONFIDENCE="MEDIUM"
      fi
    fi
  fi
fi

# ---------------------------
# Section 3: Persistence Mechanism Detection
# ---------------------------

# 3.1 Malicious VIB indicators
if [[ -n "${F_VIB_LIST}" && -f "${F_VIB_LIST}" ]]; then
  # Check for unsigned/community VIBs
  UNSIGNED_VIBS="$(grep -Ei 'CommunitySupported|PartnerSupported' "${F_VIB_LIST}" 2>/dev/null | head -n 10 || true)"
  if [[ -n "${UNSIGNED_VIBS}" ]]; then
    while IFS= read -r vib; do
      SEC_PERSISTENCE_MALICIOUS_VIBS+=("${vib}")
    done <<< "${UNSIGNED_VIBS}"
    SEC_PERSISTENCE_EVIDENCE+=("[VIB] Community/Partner supported VIBs found (review for legitimacy)")
  fi

  # Check for known malicious VIB names
  MALICIOUS_VIB_PATTERNS="$(grep -Ei 'virtualpita|virtualpie|virtualgate|vmsync|vmtools-backdoor' "${F_VIB_LIST}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${MALICIOUS_VIB_PATTERNS}" ]]; then
    SEC_PERSISTENCE_EVIDENCE+=("[CRITICAL] Known malicious VIB names detected")
    SEC_PERSISTENCE_MALICIOUS_VIBS+=("${MALICIOUS_VIB_PATTERNS}")
    # This is critical - update VM escape confidence
    SEC_VMESCAPE_CONFIDENCE="CRITICAL"
    SEC_VMESCAPE_EVIDENCE+=("[CRITICAL] Known malicious VIB detected in VIB list")
  fi
fi

# 3.2 Startup script persistence (already captured in ransomware section, consolidate here)
if [[ -n "${F_RC_LOCAL_D}" && -d "${F_RC_LOCAL_D}" ]]; then
  ALL_STARTUP="$(find "${F_RC_LOCAL_D}" -type f -name "*.sh" 2>/dev/null || true)"
  if [[ -n "${ALL_STARTUP}" ]]; then
    while IFS= read -r f; do
      SEC_PERSISTENCE_STARTUP_SCRIPTS+=("${f}")
    done <<< "${ALL_STARTUP}"
    # Check content of local.sh for suspicious additions
    LOCAL_SH="${F_RC_LOCAL_D}/local.sh"
    if [[ -f "${LOCAL_SH}" ]]; then
      SUSPICIOUS_LOCAL="$(grep -Eni 'wget|curl|chmod|python|perl|/tmp/|/scratch/|base64|nc|netcat' "${LOCAL_SH}" 2>/dev/null | head -n 5 || true)"
      if [[ -n "${SUSPICIOUS_LOCAL}" ]]; then
        SEC_PERSISTENCE_EVIDENCE+=("[STARTUP] Suspicious commands in local.sh")
      fi
    fi
  fi
fi

# 3.3 Cron job persistence
CRON_DIRS="$(find "${ROOT}" -type d \( -path "*/var/spool/cron*" -o -path "*/etc/cron*" \) 2>/dev/null || true)"
if [[ -n "${CRON_DIRS}" ]]; then
  CRON_FILES="$(find ${CRON_DIRS} -type f 2>/dev/null | head -n 10 || true)"
  if [[ -n "${CRON_FILES}" ]]; then
    SEC_PERSISTENCE_EVIDENCE+=("[CRON] Cron files detected - review for persistence")
    while IFS= read -r f; do
      SEC_PERSISTENCE_STARTUP_SCRIPTS+=("${f}")
    done <<< "${CRON_FILES}"
  fi
fi

# 3.4 Hidden files in VMFS volumes
HIDDEN_VMFS="$(find "${ROOT}" -path "*/vmfs/volumes/*" -name ".*" -type f 2>/dev/null | head -n 10 || true)"
if [[ -n "${HIDDEN_VMFS}" ]]; then
  SEC_PERSISTENCE_EVIDENCE+=("[HIDDEN] Hidden files found in VMFS volumes")
  while IFS= read -r f; do
    SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS+=("${f}")
  done <<< "${HIDDEN_VMFS}"
fi

# 3.5 Check /etc/vmware/config for modifications
F_VMWARE_CONFIG="$(find_first "${ROOT}" "/etc/vmware/config" "etc/vmware/config" || true)"
if [[ -n "${F_VMWARE_CONFIG}" && -f "${F_VMWARE_CONFIG}" ]]; then
  SUSPICIOUS_CONFIG="$(grep -Eni 'libdir|execpath|preload' "${F_VMWARE_CONFIG}" 2>/dev/null | head -n 5 || true)"
  if [[ -n "${SUSPICIOUS_CONFIG}" ]]; then
    SEC_PERSISTENCE_EVIDENCE+=("[CONFIG] Suspicious entries in /etc/vmware/config")
  fi
fi

# ---------------------------
# Output: Security Forensics Summary
# ---------------------------

log "### Ransomware Indicators"
log "- Confidence: ${SEC_RANSOMWARE_CONFIDENCE}"
if [[ "${#SEC_RANSOMWARE_ENCRYPTED_FILES[@]}" -gt 0 ]]; then
  log "- Encrypted Files Found: ${#SEC_RANSOMWARE_ENCRYPTED_FILES[@]}"
  for f in "${SEC_RANSOMWARE_ENCRYPTED_FILES[@]:0:10}"; do
    log "    - ${f}"
  done
  [[ "${#SEC_RANSOMWARE_ENCRYPTED_FILES[@]}" -gt 10 ]] && log "    - ... and $((${#SEC_RANSOMWARE_ENCRYPTED_FILES[@]} - 10)) more"
fi
if [[ "${#SEC_RANSOMWARE_RANSOM_NOTES[@]}" -gt 0 ]]; then
  log "- Ransom Notes Found: ${#SEC_RANSOMWARE_RANSOM_NOTES[@]}"
  for f in "${SEC_RANSOMWARE_RANSOM_NOTES[@]}"; do
    log "    - ${f}"
  done
fi
if [[ "${#SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS[@]}" -gt 0 ]]; then
  log "- Suspicious Scripts/Files: ${#SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS[@]}"
  for f in "${SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS[@]:0:10}"; do
    log "    - ${f}"
  done
  [[ "${#SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS[@]}" -gt 10 ]] && log "    - ... and $((${#SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS[@]} - 10)) more"
fi
if [[ "${#SEC_RANSOMWARE_EVIDENCE[@]}" -gt 0 ]]; then
  log "- Evidence:"
  for e in "${SEC_RANSOMWARE_EVIDENCE[@]}"; do
    log "    ${e}"
  done
fi
if [[ "${SEC_RANSOMWARE_CONFIDENCE}" == "NONE" ]]; then
  log "- No ransomware indicators detected"
fi
log ""

log "### VM Escape / Exploitation Indicators"
log "- Confidence: ${SEC_VMESCAPE_CONFIDENCE}"
if [[ "${#SEC_VMESCAPE_CVE_INDICATORS[@]}" -gt 0 ]]; then
  log "- CVE Indicators:"
  for c in "${SEC_VMESCAPE_CVE_INDICATORS[@]}"; do
    log "    ${c}"
  done
fi
if [[ "${#SEC_VMESCAPE_EVIDENCE[@]}" -gt 0 ]]; then
  log "- Evidence:"
  for e in "${SEC_VMESCAPE_EVIDENCE[@]}"; do
    log "    ${e}"
  done
fi
if [[ "${SEC_VMESCAPE_CONFIDENCE}" == "NONE" ]]; then
  log "- No VM escape indicators detected"
fi
log ""

log "### Persistence Mechanisms"
if [[ "${#SEC_PERSISTENCE_STARTUP_SCRIPTS[@]}" -gt 0 ]]; then
  log "- Startup Scripts: ${#SEC_PERSISTENCE_STARTUP_SCRIPTS[@]}"
  for f in "${SEC_PERSISTENCE_STARTUP_SCRIPTS[@]:0:10}"; do
    log "    - ${f}"
  done
fi
if [[ "${#SEC_PERSISTENCE_MALICIOUS_VIBS[@]}" -gt 0 ]]; then
  log "- Suspicious VIBs: ${#SEC_PERSISTENCE_MALICIOUS_VIBS[@]}"
  for v in "${SEC_PERSISTENCE_MALICIOUS_VIBS[@]:0:10}"; do
    log "    - ${v}"
  done
fi
if [[ "${#SEC_PERSISTENCE_EVIDENCE[@]}" -gt 0 ]]; then
  log "- Evidence:"
  for e in "${SEC_PERSISTENCE_EVIDENCE[@]}"; do
    log "    ${e}"
  done
fi
if [[ "${#SEC_PERSISTENCE_EVIDENCE[@]}" -eq 0 && "${#SEC_PERSISTENCE_STARTUP_SCRIPTS[@]}" -eq 0 && "${#SEC_PERSISTENCE_MALICIOUS_VIBS[@]}" -eq 0 ]]; then
  log "- No persistence indicators detected"
fi
log ""

# ---------------------------
# Log Forwarding / Remote Syslog
# ---------------------------
REMOTE_LOGHOSTS=()
REMOTE_SOURCES=()

# Tier 1: esxcli syslog config loghost get
if [[ -n "${F_ESXCLI_SYSLOG_LOGHOST}" && -f "${F_ESXCLI_SYSLOG_LOGHOST}" ]]; then
  line="$(grep -E -m 1 'Loghost:' "${F_ESXCLI_SYSLOG_LOGHOST}" 2>/dev/null || true)"
  if [[ -n "${line}" ]]; then
    hosts="$(echo "${line}" | sed 's/.*Loghost:\s*//')"
    IFS=',' read -r -a arr <<< "${hosts}"
    for h in "${arr[@]}"; do
      [[ -n "${h// /}" ]] && REMOTE_LOGHOSTS+=("${h// /}") || true
    done
    REMOTE_SOURCES+=("${F_ESXCLI_SYSLOG_LOGHOST}")
  fi
fi

# Tier 2: vmsyslog.conf
if [[ "${#REMOTE_LOGHOSTS[@]}" -eq 0 && -n "${F_SYSLOG_CFG}" && -f "${F_SYSLOG_CFG}" ]]; then
  hosts="$(grep -E -m 1 'loghost|LogHost|RemoteHost|logHost' "${F_SYSLOG_CFG}" 2>/dev/null | sed -nE "s/.*['\"](udp|tcp|ssl):\/\/([^'\"]+)['\"].*/\1:\/\/\2/p" || true)"
  if [[ -n "${hosts}" ]]; then
    REMOTE_LOGHOSTS+=("${hosts}")
    REMOTE_SOURCES+=("${F_SYSLOG_CFG}")
  fi
fi

# Tier 3: syslog config get
if [[ "${#REMOTE_LOGHOSTS[@]}" -eq 0 && -n "${F_ESXCLI_SYSLOG_CFG}" && -f "${F_ESXCLI_SYSLOG_CFG}" ]]; then
  line="$(grep -E -m 1 'Loghost:' "${F_ESXCLI_SYSLOG_CFG}" 2>/dev/null || true)"
  if [[ -n "${line}" ]]; then
    hosts="$(echo "${line}" | sed 's/.*Loghost:\s*//')"
    IFS=',' read -r -a arr <<< "${hosts}"
    for h in "${arr[@]}"; do
      [[ -n "${h// /}" ]] && REMOTE_LOGHOSTS+=("${h// /}") || true
    done
    REMOTE_SOURCES+=("${F_ESXCLI_SYSLOG_CFG}")
  fi
fi

# Tier 4: rsyslog.conf
if [[ "${#REMOTE_LOGHOSTS[@]}" -eq 0 && -n "${F_RSYSLOG_CFG}" && -f "${F_RSYSLOG_CFG}" ]]; then
  target="$(grep -E -m 1 '^\s*\*\.\*.*(@@|@)[A-Za-z0-9\.\-]+' "${F_RSYSLOG_CFG}" 2>/dev/null || true)"
  if [[ -n "${target}" ]]; then
    REMOTE_LOGHOSTS+=("${target}")
    REMOTE_SOURCES+=("${F_RSYSLOG_CFG}")
  fi
fi

log "## Log Forwarding / Remote Syslog"
if [[ "${#REMOTE_LOGHOSTS[@]}" -gt 0 ]]; then
  log "- Remote log hosts configured: YES"
  for h in "${REMOTE_LOGHOSTS[@]}"; do
    log "  - ${h}"
  done
  for s in "${REMOTE_SOURCES[@]}"; do
    log "- Source: ${s}"
  done
else
  log "- Remote log hosts configured: No evidence found (or syslog config outputs missing from bundle)."
  [[ -n "${F_ESXCLI_SYSLOG_LOGHOST}" ]] && log "- Source checked: ${F_ESXCLI_SYSLOG_LOGHOST}" || true
  [[ -n "${F_ESXCLI_SYSLOG_CFG}" ]] && log "- Source checked: ${F_ESXCLI_SYSLOG_CFG}" || true
  [[ -n "${F_SYSLOG_CFG}" ]] && log "- Source checked: ${F_SYSLOG_CFG}" || true
  [[ -n "${F_RSYSLOG_CFG}" ]] && log "- Source checked: ${F_RSYSLOG_CFG}" || true
fi
log ""

# ---------------------------
# Security Context (Auth/Shell Evidence)
# ---------------------------
log "## Quick Context (Auth/Shell Evidence)"
if [[ -n "${F_AUTH}" && -f "${F_AUTH}" ]]; then
  log "- auth.log source: ${F_AUTH}"
  grep -E 'Accepted|Failed|authentication|root|ssh' "${F_AUTH}" 2>/dev/null | tail -n 40 | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
else
  log "- auth.log not found in bundle."
fi

if [[ -n "${F_SHELL}" && -f "${F_SHELL}" ]]; then
  log ""
  log "- shell.log source: ${F_SHELL}"
  grep -E 'enable|disable|SSH|ESXi Shell|TSM|DCUI|ESXShell' "${F_SHELL}" 2>/dev/null | tail -n 60 | sed 's/^/  /' | tee -a "${REPORT_TXT}" >/dev/null || true
else
  log "- shell.log not found in bundle."
fi
log ""

# ---------------------------
# JSON output (complete structured fields)
# ---------------------------

# Build sources array helper
json_array() {
  local arr=("$@")
  local result="["
  local first=1
  for item in "${arr[@]}"; do
    if [[ "${first}" -eq 1 ]]; then
      first=0
    else
      result+=", "
    fi
    result+="\"$(printf "%s" "${item}" | json_escape)\""
  done
  result+="]"
  echo "${result}"
}

remote_json="$(json_array "${REMOTE_LOGHOSTS[@]:-}")"
vc_sources_json="$(json_array "${VC_SOURCES[@]:-}")"
vc_evidence_json="$(json_array "${VC_EVIDENCE[@]:-}")"
vsan_sources_json="$(json_array "${VSAN_SOURCES[@]:-}")"
vsan_evidence_json="$(json_array "${VSAN_EVIDENCE[@]:-}")"
hostname_sources_json="$(json_array "${HOSTNAME_SOURCES[@]:-}")"
product_hits_json="$(json_array "${PRODUCT_HITS[@]:-}")"

# DNS JSON arrays
dns_servers_json="$(json_array "${DNS_SERVERS[@]:-}")"
dns_search_json="$(json_array "${DNS_SEARCH_DOMAINS[@]:-}")"
dns_hosts_json="$(json_array "${HOSTS_ENTRIES[@]:-}")"
dns_sources_json="$(json_array "${DNS_SOURCES[@]:-}")"

# Security forensics JSON arrays
sec_ransomware_encrypted_json="$(json_array "${SEC_RANSOMWARE_ENCRYPTED_FILES[@]:-}")"
sec_ransomware_notes_json="$(json_array "${SEC_RANSOMWARE_RANSOM_NOTES[@]:-}")"
sec_ransomware_scripts_json="$(json_array "${SEC_RANSOMWARE_SUSPICIOUS_SCRIPTS[@]:-}")"
sec_ransomware_evidence_json="$(json_array "${SEC_RANSOMWARE_EVIDENCE[@]:-}")"
sec_vmescape_cve_json="$(json_array "${SEC_VMESCAPE_CVE_INDICATORS[@]:-}")"
sec_vmescape_evidence_json="$(json_array "${SEC_VMESCAPE_EVIDENCE[@]:-}")"
sec_persistence_startup_json="$(json_array "${SEC_PERSISTENCE_STARTUP_SCRIPTS[@]:-}")"
sec_persistence_vibs_json="$(json_array "${SEC_PERSISTENCE_MALICIOUS_VIBS[@]:-}")"
sec_persistence_evidence_json="$(json_array "${SEC_PERSISTENCE_EVIDENCE[@]:-}")"
sec_config_findings_json="$(json_array "${SEC_CONFIG_FINDINGS[@]:-}")"

{
  echo "{"
  echo "  \"input\": \"$(printf "%s" "${INPUT}" | json_escape)\","
  echo "  \"root\": \"$(printf "%s" "${ROOT}" | json_escape)\","
  echo "  \"esxi\": {"
  echo "    \"hostname\": \"$(printf "%s" "${ESXI_HOSTNAME:-UNKNOWN}" | json_escape)\","
  echo "    \"domain\": \"$(printf "%s" "${ESXI_DOMAINNAME:-}" | json_escape)\","
  echo "    \"version\": \"$(printf "%s" "${ESXI_VERSION:-UNKNOWN}" | json_escape)\","
  echo "    \"build\": \"$(printf "%s" "${ESXI_BUILD:-UNKNOWN}" | json_escape)\","
  echo "    \"uuid\": \"$(printf "%s" "${SYSTEM_UUID:-}" | json_escape)\","
  echo "    \"inception\": \"$(printf "%s" "${SYSTEM_INCEPTION:-}" | json_escape)\","
  echo "    \"vib_acceptance_level\": \"$(printf "%s" "${VIB_ACCEPTANCE_LEVEL:-}" | json_escape)\","
  echo "    \"management_ip\": \"$(printf "%s" "${MGMT_IP:-}" | json_escape)\","
  echo "    \"hostname_sources\": ${hostname_sources_json}"
  echo "  },"
  echo "  \"dns\": {"
  echo "    \"servers\": ${dns_servers_json},"
  echo "    \"search_domains\": ${dns_search_json},"
  echo "    \"hosts_entries\": ${dns_hosts_json},"
  echo "    \"resolv_conf\": \"$(printf "%s" "${F_RESOLV_CONF:-}" | json_escape)\","
  echo "    \"sources\": ${dns_sources_json}"
  echo "  },"
  echo "  \"vcenter\": {"
  echo "    \"managed\": \"$(printf "%s" "${VC_MANAGED}" | json_escape)\","
  echo "    \"hostname\": \"$(printf "%s" "${VC_HOST:-UNKNOWN}" | json_escape)\","
  echo "    \"ip\": \"$(printf "%s" "${VC_IP:-UNKNOWN}" | json_escape)\","
  echo "    \"sources\": ${vc_sources_json},"
  echo "    \"evidence\": ${vc_evidence_json}"
  echo "  },"
  echo "  \"vsan\": {"
  echo "    \"indicated\": \"$(printf "%s" "${VSAN_PRESENT}" | json_escape)\","
  echo "    \"sources\": ${vsan_sources_json},"
  echo "    \"evidence\": ${vsan_evidence_json}"
  echo "  },"
  echo "  \"syslog\": {"
  echo "    \"remote_loghosts\": ${remote_json}"
  echo "  },"
  echo "  \"products\": ${product_hits_json},"
  echo "  \"security\": {"
  echo "    \"ransomware\": {"
  echo "      \"confidence\": \"$(printf "%s" "${SEC_RANSOMWARE_CONFIDENCE}" | json_escape)\","
  echo "      \"encrypted_files\": ${sec_ransomware_encrypted_json},"
  echo "      \"ransom_notes\": ${sec_ransomware_notes_json},"
  echo "      \"suspicious_scripts\": ${sec_ransomware_scripts_json},"
  echo "      \"evidence\": ${sec_ransomware_evidence_json}"
  echo "    },"
  echo "    \"vm_escape\": {"
  echo "      \"confidence\": \"$(printf "%s" "${SEC_VMESCAPE_CONFIDENCE}" | json_escape)\","
  echo "      \"cve_indicators\": ${sec_vmescape_cve_json},"
  echo "      \"evidence\": ${sec_vmescape_evidence_json}"
  echo "    },"
  echo "    \"persistence\": {"
  echo "      \"startup_scripts\": ${sec_persistence_startup_json},"
  echo "      \"suspicious_vibs\": ${sec_persistence_vibs_json},"
  echo "      \"evidence\": ${sec_persistence_evidence_json}"
  echo "    },"
  echo "    \"config_findings\": ${sec_config_findings_json}"
  echo "  },"
  echo "  \"logs\": {"
  echo "    \"var_log\": \"$(printf "%s" "${LOG_DIR_VARLOG:-}" | json_escape)\","
  echo "    \"var_run_log\": \"$(printf "%s" "${LOG_DIR_VARRUNLOG:-}" | json_escape)\","
  echo "    \"vmkernel\": \"$(printf "%s" "${F_VMKERNEL:-}" | json_escape)\","
  echo "    \"syslog\": \"$(printf "%s" "${F_SYSLOG:-}" | json_escape)\","
  echo "    \"hostd\": \"$(printf "%s" "${F_HOSTD:-}" | json_escape)\","
  echo "    \"vpxa\": \"$(printf "%s" "${F_VPXA:-}" | json_escape)\","
  echo "    \"auth\": \"$(printf "%s" "${F_AUTH:-}" | json_escape)\","
  echo "    \"shell\": \"$(printf "%s" "${F_SHELL:-}" | json_escape)\""
  echo "  },"
  echo "  \"storage\": {"
  echo "    \"filesystem_list\": \"$(printf "%s" "${F_FS_LIST:-}" | json_escape)\","
  echo "    \"vmfs_extents\": \"$(printf "%s" "${F_VMFS_EXTENTS:-}" | json_escape)\","
  echo "    \"nfs_list\": \"$(printf "%s" "${F_NFS_LIST:-}" | json_escape)\","
  echo "    \"iscsi_adapters\": \"$(printf "%s" "${F_ISCSI_ADAPTERS:-}" | json_escape)\""
  echo "  },"
  echo "  \"networking\": {"
  echo "    \"pnics\": \"$(printf "%s" "${F_PNICS:-}" | json_escape)\","
  echo "    \"vmk_nics\": \"$(printf "%s" "${F_VMK_NICS:-}" | json_escape)\","
  echo "    \"vswitch\": \"$(printf "%s" "${F_VSWITCH:-}" | json_escape)\","
  echo "    \"dvswitch\": \"$(printf "%s" "${F_DVS:-}" | json_escape)\","
  echo "    \"portgroups\": \"$(printf "%s" "${F_PORTGROUPS:-}" | json_escape)\","
  echo "    \"firewall_rules\": \"$(printf "%s" "${F_FW_RULES:-}" | json_escape)\","
  echo "    \"firewall_allowed\": \"$(printf "%s" "${F_FW_ALLOWED:-}" | json_escape)\""
  echo "  }"
  echo "}"
} > "${REPORT_JSON}"

log "============================================================"
log "Output written to:"
log "- ${REPORT_TXT}"
log "- ${REPORT_JSON}"
log "============================================================"
