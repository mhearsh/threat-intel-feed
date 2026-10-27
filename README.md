<p align="center"><img src="assets/banner.svg" alt="threat-intel-feed banner" width="100%"></p>

<p align="center">
<a href="https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json"><img src="https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json&amp;query=$.updated&amp;label=last%20update&amp;color=7b2ff7" alt="last update"></a>
<a href="https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json"><img src="https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json&amp;query=$.count&amp;label=IOCs&amp;color=00b3a8" alt="IOCs"></a>
<a href="https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json"><img src="https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json&amp;query=$.fresh_6h&amp;label=fresh%20%3C6h&amp;color=e05d44" alt="fresh &lt;6h"></a>
<a href="https://github.com/mhearsh/threat-intel-feed/commits/main"><img src="https://img.shields.io/badge/updates-every%202h-blue" alt="updates every 2h"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/data-CC%20BY%204.0-lightgrey" alt="data license CC BY 4.0"></a>
<a href="https://github.com/mhearsh/threat-intel-feed/releases/latest"><img src="https://img.shields.io/github/v/release/mhearsh/threat-intel-feed" alt="release"></a>
<a href="https://mhearsh.github.io/threat-intel-feed/guide/IOC-Feed-Integration-Guide.pdf"><img src="https://img.shields.io/badge/guide-PDF%20%2B%20MD-0aa5b8" alt="integration guide"></a>
<a href="https://mhearsh.github.io/threat-intel-feed/"><img src="https://img.shields.io/badge/feeds-GitHub%20Pages-222" alt="feeds on GitHub Pages"></a>
<a href="feeds/generic/stix/stix21.json"><img src="https://img.shields.io/badge/STIX-2.1-purple" alt="STIX 2.1"></a>
</p>

> A short, curated blocklist of **active, high-confidence** malicious infrastructure (C2, malware delivery, phishing), with ready-to-import files for firewalls, EDR/XDR and SIEM/SOAR platforms. It is regenerated every 2 hours.

<p align="center"><b>📘 <a href="https://mhearsh.github.io/threat-intel-feed/guide/IOC-Feed-Integration-Guide.pdf">Integration guide (PDF)</a> · <a href="https://mhearsh.github.io/threat-intel-feed/guide/GUIDE.md">Integration guide (Markdown)</a> · <a href="https://mhearsh.github.io/threat-intel-feed/">Feed index</a></b></p>

## At a glance
| | |
|---|---|
| **IOC types** | IPv4 addresses, domains (FQDN), URLs (no scheme), file hashes (SHA-256, SHA-1, MD5) |
| **Score** | 0–100; only **≥ 50** is published. Bands: **critical 90–100 · high 75–89 · medium 50–74** |
| **Update frequency** | Every 2 hours (commit only when data changes); entries expire after 30 days |
| **Formats** | Plain text (one per line), vendor CSV/JSON, STIX 2.1 |
| **Platforms** | Palo Alto, FortiGate, Check Point, Cisco FMC, Sophos, Suricata · Defender, CrowdStrike, SentinelOne, ESET, Trend Vision One, Cortex XDR · Sentinel, Splunk ES, Wazuh, MISP/OpenCTI |
| **Base URL** | `https://mhearsh.github.io/threat-intel-feed/feeds/` (raw fallback: `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/feeds/<path>`) |

## Table of contents
- [At a glance](#at-a-glance)
- [Why this feed](#why-this-feed)
- [Methodology](#methodology)
- [Quick start](#quick-start)
- [Files](#files)
- [Score scale](#score-scale)
- [Today's stats](#todays-stats)
- [FAQ](#faq)
- [Reporting false positives](#reporting-false-positives)
- [Sources and licenses](#sources-and-licenses)
- [Disclaimer](#disclaimer)

## Why this feed
- **Signal, not volume.** You get 20–50 indicators per run instead of millions. Each one is tied to a named family or C2 framework and is corroborated or high-confidence.
- **Freshness first.** Indicators first seen in the last 6–24h are ranked highest, and anything older than 72h falls out.
- **Ready to import.** Native formats for FortiGate, Palo Alto, Sentinel/Defender, Suricata and STIX 2.1, with stable URLs.
- **Context included.** Every IOC carries its family, a context line, MITRE ATT&CK techniques and its sources.

## Methodology
```mermaid
flowchart LR
  A[ThreatFox · C2IntelFeeds · OpenPhish] --> N[Normalize & dedupe<br/>SQLite]
  C[Spamhaus DROP · IPsum] -->|corroboration| S
  N --> S{Score}
  S -->|score ≥ 50 of 100<br/>conf ≥ 75 or ≥ 2 sources<br/>age < 72h| K[Keep]
  S -->|private · CDN · sinkhole · stale| X[Drop]
  K --> T[Top 50 · diversity cap]
  T --> O[FortiGate · PAN EDL · Sentinel · KQL · Suricata · STIX]
```
See [docs/methodology.md](docs/methodology.md) for the full scoring model.

## Quick start
Full step-by-step guide for every platform: **[Integration guide](https://mhearsh.github.io/threat-intel-feed/guide/GUIDE.md)** ([PDF](https://mhearsh.github.io/threat-intel-feed/guide/IOC-Feed-Integration-Guide.pdf)). Base URL: `https://mhearsh.github.io/threat-intel-feed/feeds/`.

| Platform | Feed URL(s) |
|---|---|
| **Palo Alto NGFW** (EDL) | [`edl-ip.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/paloalto/edl-ip.txt) · [`edl-domain.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/paloalto/edl-domain.txt) · [`edl-url.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/paloalto/edl-url.txt) |
| **FortiGate** (Threat Feeds) | [`ip.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/fortinet/ip.txt) · [`domain.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/fortinet/domain.txt) · [`url.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/fortinet/url.txt) · [`hash-sha256.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/fortinet/hash-sha256.txt) |
| **Check Point** (Custom Intelligence Feeds) | [`ioc-feed.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/checkpoint/ioc-feed.csv) (native format; IP, domain, URL, MD5, SHA1, SHA256) |
| **Cisco Secure Firewall / FMC** | [`ip.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/cisco/ip.txt) + [`.md5`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/cisco/ip.txt.md5) · [`url.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/cisco/url.txt) + [`.md5`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/cisco/url.txt.md5) |
| **Sophos Firewall** | [`ip.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/sophos/ip.txt) · [`domain.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/sophos/domain.txt) · [`url.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/firewall/sophos/url.txt) |
| **Suricata** | `suricata-update add-source tif https://mhearsh.github.io/threat-intel-feed/feeds/firewall/suricata/suricata.rules` |
| **Microsoft Defender for Endpoint** | [`files-001.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/microsoft-defender/files-001.csv) · [`network-001.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/microsoft-defender/network-001.csv) (≤500 rows per file, more files `-002`… when needed) · [`hunt.kql`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/microsoft-defender/hunt.kql) |
| **CrowdStrike Falcon** (API helper) | [`iocs-api.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/crowdstrike/iocs-api.csv): IOC API fields for FalconPy / PSFalcon. Falcon has no documented native CSV import. |
| **SentinelOne** | [`iocs.json`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/sentinelone/iocs.json), ready-to-POST body for the Threat Intelligence IOC API |
| **ESET PROTECT** | [`sha256.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/eset/sha256.txt) · [`sha1.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/eset/sha1.txt) |
| **Trend Vision One** | [`suspicious-objects.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/trendmicro/suspicious-objects.csv) |
| **Cortex XDR** | [`iocs.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/edr/cortex-xdr/iocs.csv) |
| **Microsoft Sentinel** | [`stix21-objects.json`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/microsoft-sentinel/stix21-objects.json) (TI *Import using a file*, JSON array template) · [`stix21.json`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/microsoft-sentinel/stix21.json) (STIX bundle) · [`watchlist.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/microsoft-sentinel/watchlist.csv) |
| **Splunk ES** | [`ip_intel.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/splunk/ip_intel.csv) · [`domain_intel.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/splunk/domain_intel.csv) · [`file_intel.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/splunk/file_intel.csv) · [`http_intel.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/splunk/http_intel.csv) |
| **Wazuh** (CDB lists) | [`cdb-ip.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/wazuh/cdb-ip.txt) · [`cdb-domain.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/wazuh/cdb-domain.txt) · [`cdb-sha256.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/siem-soar/wazuh/cdb-sha256.txt) |
| **Generic** (MISP, OpenCTI, QRadar, XSOAR, pfSense…) | [`ip.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/generic/txt/ip.txt) · [`domain.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/generic/txt/domain.txt) · [`url.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/generic/txt/url.txt) · [`sha256.txt`](https://mhearsh.github.io/threat-intel-feed/feeds/generic/txt/sha256.txt) · [`iocs.csv`](https://mhearsh.github.io/threat-intel-feed/feeds/generic/csv/iocs.csv) · [`stix21.json`](https://mhearsh.github.io/threat-intel-feed/feeds/generic/stix/stix21.json) |

More: [docs/integrations.md](docs/integrations.md).

## Files
| Path | Description |
|---|---|
| `feeds/generic/` | One type per file: `txt/` (ip, domain, url, sha256, sha1, md5 + `.md5` checksums), `csv/iocs.csv` (all types, **not** defanged), `csv/file-hashes.csv`, `stix/stix21.json` |
| `feeds/firewall/<vendor>/` | Palo Alto, Fortinet, Check Point, Cisco, Sophos, Suricata |
| `feeds/edr/<vendor>/` | Microsoft Defender, CrowdStrike, SentinelOne, ESET, Trend Micro, Cortex XDR |
| `feeds/siem-soar/<vendor>/` | Microsoft Sentinel, Splunk, Wazuh |
| `reports/` | Human-readable, defanged: `top-iocs.csv`, `blocklist-defanged.txt` |
| `latest/` | **Compatibility mirror**: the original filenames (`fortigate-ip-feed.txt`, `paloalto-edl-*.txt`, `defender-indicators.csv`, …), kept online |
| `archive/YYYY-MM-DD/` | Daily snapshots |
| `scripts/` | `build_feeds.py` (builds `feeds/`), `validate_feeds.py` (format checks run before every commit) |
| `stats.json` | Machine-readable stats (drives the badges) |

Raw fallback for any path: `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/<path>`.

## Score scale
Every IOC gets a **score from 0 to 100** (`score` and `band` columns in the CSVs, `confidence` and a `band:` label in STIX). Only scores of 50 and above are published.

| Score | Band | Suggested action |
|---|---|---|
| 90–100 | critical | Block |
| 75–89 | high | Block |
| 50–74 | medium | Alert / hunt |

Details: [docs/methodology.md](docs/methodology.md#score-scale).

## Today's stats
_Last update: 2026-10-27 06:11 UTC. 50 IOCs (ip: 14, sha256: 12, domain: 12, url: 12); 40 first seen under 6h ago. File-hash feed: 3395 SHA-256 · 222 SHA-1 · 224 MD5._

<img src="assets/families.svg" alt="family breakdown" width="100%">

| # | IOC (defanged) | Type | Family | Score | Band | ATT&CK |
|---|---|---|---|---|---|---|
| 1 | `172[.]111[.]150[.]134` | ip | Remcos | 83 | high | T1071, T1105 |
| 2 | `31[.]56[.]19[.]71` | ip | Potassium | 77 | high | T1071, T1105 |
| 3 | `68[.]64[.]176[.]76` | ip | Cobaltstrike | 77 | high | T1071, T1105 |
| 4 | `075a461396a0190568cda5cc87cc70353d14a41b80583a43a21eee6c24e3` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 5 | `0773662a47cf05cd22d72d922d2b5d43d89d0d0289ab082e308a17e79dd3` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 6 | `12ac4dbc9ad20c080c427e1e8705a510a5dea02743e3d8ea7fce42a40767` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 7 | `13d864079ad88236587cb334626d19f1c122727f0854c07d8bcb68708d25` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 8 | `1a7b5f21248130ca08aa4d43aef8b0daeeff2acbd8035e56d29e31c2dd44` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 9 | `2q2spejlgz2x5haqe3ygclxj6jwlylgj5rg4jgwax6ub2fbpct27ibyd[.]o` | domain | DragonForce | 74 | medium | T1071, T1105 |
| 10 | `30b82d9a64842674a296c6e26c6dfc45b5577b642980340f4c51c4f9e797` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 11 | `3146160dbe03a9adde20be6383fc25b354c590c15a92d9cdccf3ad97df98` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 12 | `34[.]41[.]139[.]193` | ip | Nanocore RAT | 74 | medium | T1071, T1105 |
| 13 | `453e5d436ce3a6a8869f818f77d65c67e72c418e64c31d95b203a663fdfb` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 14 | `47c6951f574579b287b34d9d3e8e1ddb72b284cf077f24b1683900ff8015` | sha256 | AMOS | 74 | medium | T1071, T1105 |
| 15 | `5013096c19981a3800bb7580dd63f08f2a3c9e237a7c329cd2dcc9a0180c` | sha256 | AMOS | 74 | medium | T1071, T1105 |

## FAQ
**How often does it update?** Every 2 hours. A commit is made only when the data changes.<br>
**Why so few entries?** On purpose. The list is tuned for blocking with a low false-positive rate.<br>
**Are the values defanged?** Only in the `top-iocs.csv` and `blocklist-defanged.txt` files. The platform files contain live values so they can be imported directly.<br>
**What do the .txt lists look like?** Like a classic IOC list: an 11-line `#` title banner (title, purpose, format, usage, `Updated` UTC, `Count`, `Expiry`), then dated blocks, newest first. Each block has 3 comment lines (source or campaign, `TLP:CLEAR - Threat Level: …`, `YYYY-MM-DD` = the date the IOC first entered the feed) followed by sorted, live (not defanged) values. Lists are cumulative: an IOC stays for 30 days after it was last seen. Every line is validated before publishing.<br>
**My firewall rejects `#` lines.** Use the `-plain.txt` copy next to each Palo Alto / FortiGate file (same values, no comments). Cisco FMC accepts `#` comments, so its lists are titled. Sophos and ESET files stay comment-free (a titled `-titled.txt` copy sits next to them for humans). Wazuh CDB stays `key:value`.<br>
**Where is the date of addition in structured files?** CSV: a `first_published` / `FirstPublished` column, or `added YYYY-MM-DD` in the vendor's description/comment field when the import schema is fixed. STIX: `created` / `valid_from`. Suricata: `metadata:created_at`. KQL: a `FirstPublished` datatable column. Wazuh CDB and SentinelOne: `added YYYY-MM-DD` in the value/description.<br>
**Can I use it commercially?** Our data is CC BY 4.0, but Spamhaus DROP-derived corroboration is non-commercial. See [LICENSE](LICENSE).

## Reporting false positives
Open a [False positive issue](../../issues/new?template=false-positive.yml) with the indicator and your evidence. Confirmed entries are allow-listed in the next run.

## Sources and licenses
| Source | License / terms |
|---|---|
| [abuse.ch ThreatFox](https://threatfox.abuse.ch) | CC0 1.0 |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Free for non-commercial use (Spamhaus terms) |
| [OpenPhish Community](https://openphish.com) | Free community feed, attribution, no resale |
| [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds) | Public feed, attribution |
| [IPsum](https://github.com/stamparm/ipsum) | Unlicense |
| [Curated](curated/) | Manually added indicators listed on official sources only (vendor advisories, CISA, national CERTs); each entry links its source |

## Changelog
Full history: [CHANGELOG.md](CHANGELOG.md).

- **2026-10-26:** titled, dated `.txt` lists (banner + dated blocks, newest first), cumulative with 30-day expiry, `-plain.txt` comment-free copies for Palo Alto / FortiGate, strict per-line IOC validation.
- **2026-10-24:** new `feeds/` layout (generic + per-vendor folders), feeds served from GitHub Pages, new vendor formats (Check Point, Cisco `.md5`, Trend Vision One, Cortex XDR, SentinelOne, Splunk, Wazuh), Defender split into ≤500-row files, separate `url.txt` / `domain.txt`, generic non-defanged `iocs.csv`. `latest/` stays as a compatibility mirror.
- **2026-10-24:** new file-hash feed (SHA-256 / SHA-1 / MD5 lists, Defender and CrowdStrike import CSVs, STIX `file:hashes`).
- **2026-10-24:** scores are now on a documented 0–100 scale with bands (breaking for consumers of `score`/`confidence`); the Palo Alto URL EDL no longer contains bare IPs or trailing `/` (IP hosts moved to the IP EDLs); drop CSVs no longer start with a `#` comment line.

## Disclaimer
This feed is provided **as is**, without warranty. Indicators can go stale or produce false positives, for example on reassigned shared infrastructure. Validate before you block in production. Never browse to the listed indicators.
