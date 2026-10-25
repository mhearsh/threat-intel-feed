# IOC Feed Integration Guide
_Open threat-intel feed · github.com/mhearsh/threat-intel-feed_

Scores 0–100: **Critical 90–100 · High 75–89 · Medium 50–74**. Feeds refresh every 2 hours. Entries expire after 30 days.

> ● = available now. Raw fallback: `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/feeds/...`. Legacy `latest/` paths stay online as a compatibility mirror.

## Firewalls — Palo Alto NGFW
External Dynamic Lists (pull, HTTPS).

1. Objects → External Dynamic Lists → Add. Create one list per type: IP, Domain, URL.
2. Paste the source URL below and set Repeat to Hourly.
3. Reference the EDL in a Security policy with action Deny or Drop.
4. Commit, then check List Capacities.

- ● **IP:** `https://mhearsh.github.io/threat-intel-feed/feeds/firewall/paloalto/edl-ip.txt`
- ● **Domain:** `https://mhearsh.github.io/threat-intel-feed/feeds/firewall/paloalto/edl-domain.txt`
- ● **URL:** `https://mhearsh.github.io/threat-intel-feed/feeds/firewall/paloalto/edl-url.txt`

## Firewalls — Fortinet FortiGate
Security Fabric → External Connectors → Threat Feeds.

1. Create an IP Address, Domain Name, URL, or Malware Hash feed.
2. Enter the URL below. Set refresh to 60 min.
3. Use the feed in a firewall policy, DNS filter, web filter, or AV profile.
4. Use one hash algorithm per feed.

- ● **IP:** `https://mhearsh.github.io/threat-intel-feed/feeds/firewall/fortinet/ip.txt`
- ● **Domain:** `https://mhearsh.github.io/threat-intel-feed/feeds/firewall/fortinet/domain.txt`
- ● **SHA-256:** `https://mhearsh.github.io/threat-intel-feed/feeds/firewall/fortinet/hash-sha256.txt`

## Firewalls — Check Point · Cisco · Sophos · pfSense
Plain-text pull feeds. Check Point uses its native CSV.

1. Check Point: `ioc_feeds add --feed_name tif --transport https --resource <URL>`, or add it in SmartConsole → Custom Intelligence Feeds.
2. Cisco FMC: Objects → Security Intelligence → Network/URL feed. Add the .md5 URL for intervals of 30 min or less.
3. Sophos XGS: Active Threat Response → Third-party threat feeds. Create one feed per type.
4. pfSense/OPNsense: URL Table alias or a pfBlockerNG list.

- ● **Check Point CSV:** `https://mhearsh.github.io/threat-intel-feed/feeds/firewall/checkpoint/ioc-feed.csv`
- ● **Generic IP:** `https://mhearsh.github.io/threat-intel-feed/feeds/generic/txt/ip.txt`
- ● **Generic URL:** `https://mhearsh.github.io/threat-intel-feed/feeds/generic/txt/url.txt`

## EDR — Microsoft Defender for Endpoint
Settings → Endpoints → Indicators → Import. Maximum 500 rows per file. SHA-1 and SHA-256 only.

1. Download the file CSV below.
2. Select the matching tab (File hashes, or IP addresses / URLs).
3. Import → Choose file → Import.
4. Review the actions (Audit or Block) and the expiration date.

- ● **File hashes:** `https://mhearsh.github.io/threat-intel-feed/feeds/edr/microsoft-defender/files-001.csv`
- ● **Network:** `https://mhearsh.github.io/threat-intel-feed/feeds/edr/microsoft-defender/network-001.csv`

## EDR — CrowdStrike · SentinelOne · ESET
Import through the API, or paste the hashes.

1. CrowdStrike: import the CSV with FalconPy or PSFalcon (IOC API).
2. SentinelOne: POST the JSON to /web/api/v2.1/threat-intelligence/iocs.
3. ESET PROTECT: Blocked hashes → Add hashes. Paste the SHA-256 or SHA-1 list.

- ● **CrowdStrike:** `https://mhearsh.github.io/threat-intel-feed/feeds/edr/crowdstrike/iocs-api.csv`
- ● **SentinelOne:** `https://mhearsh.github.io/threat-intel-feed/feeds/edr/sentinelone/iocs.json`
- ● **ESET SHA-256:** `https://mhearsh.github.io/threat-intel-feed/feeds/edr/eset/sha256.txt`

## EDR — Trend Vision One · Cortex XDR
CSV import.

1. Trend: Threat Intelligence → Suspicious Object Management → Import (max 2,000 objects / 1 MB).
2. Cortex XDR: Detection Rules → IOC → Import CSV.

- ● **Trend Vision One:** `https://mhearsh.github.io/threat-intel-feed/feeds/edr/trendmicro/suspicious-objects.csv`
- ● **Cortex XDR:** `https://mhearsh.github.io/threat-intel-feed/feeds/edr/cortex-xdr/iocs.csv`

## SIEM / SOAR
STIX 2.1 for TI platforms. Typed CSV for Splunk.

1. Microsoft Sentinel: Threat intelligence → Import → Import using a file → JSON. Use the array file (Sentinel JSON template); the STIX bundle stays available for other tools.
2. Splunk ES: Threat intelligence → Data sources → URL. Use the ip_intel, domain_intel, http_intel and file_intel CSVs.
3. MISP / OpenCTI / XSOAR: add the STIX file or the generic CSV as a feed.
4. QRadar / Wazuh: load the generic txt into a reference set or CDB list.

- ● **Sentinel JSON:** `https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/microsoft-sentinel/stix21-objects.json`
- ● **STIX 2.1:** `https://mhearsh.github.io/threat-intel-feed/feeds/generic/stix/stix21.json`
- ● **Splunk ip_intel:** `https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/splunk/ip_intel.csv`
- ● **Generic CSV:** `https://mhearsh.github.io/threat-intel-feed/feeds/generic/csv/iocs.csv`

---

**Eliran Emuna — Cyber Security**  
Threat Intelligence Feed · 2026