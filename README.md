<p align="center"><img src="assets/banner.svg" alt="threat-intel-feed banner" width="100%"></p>

<p align="center">
<a href="https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json"><img src="https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json&amp;query=$.updated&amp;label=last%20update&amp;color=7b2ff7" alt="last update"></a>
<a href="https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json"><img src="https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json&amp;query=$.count&amp;label=IOCs&amp;color=00b3a8" alt="IOCs"></a>
<a href="https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json"><img src="https://img.shields.io/badge/dynamic/json?url=https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/stats.json&amp;query=$.fresh_6h&amp;label=fresh%20%3C6h&amp;color=e05d44" alt="fresh &lt;6h"></a>
<a href="https://github.com/mhearsh/threat-intel-feed/commits/main"><img src="https://img.shields.io/badge/updates-every%202h-blue" alt="updates every 2h"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/data-CC%20BY%204.0-lightgrey" alt="data license CC BY 4.0"></a>
<a href="latest/stix21.json"><img src="https://img.shields.io/badge/STIX-2.1-purple" alt="STIX 2.1"></a>
</p>

> A short, curated blocklist of **active, high-confidence** malicious infrastructure (C2, malware delivery, phishing), with ready-to-import files for every major security platform. It is regenerated every 2 hours.

## Table of contents
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
| Platform | URL / steps |
|---|---|
| **FortiGate** | *Security Fabric → External Connectors → Create New → Threat Feeds → IP Address*. URI `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/fortigate-ip-feed.txt`, refresh 60 min. Use it as the destination in a DENY policy. For domains, use the *Domain Name* type with `fortigate-domain-feed.txt` and reference it in DNS Filter. |
| **Palo Alto** | *Objects → External Dynamic Lists → Add*. Type *IP List*, source `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/paloalto-edl-ip.txt`, Hourly. Add a *URL List* with `paloalto-edl-url.txt` and reference both in your security / URL-filtering rules. |
| **Microsoft Sentinel** | *Watchlists → New*. Upload `latest/sentinel-watchlist.csv` with search key `Indicator`. |
| **Defender XDR** | Paste `latest/defender-hunt.kql` into Advanced Hunting, or save it as a custom detection. |
| **Suricata** | `suricata-update add-source tif https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/suricata.rules && suricata-update` |
| **STIX / TAXII / MISP / OpenCTI** | Ingest `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/stix21.json` as a STIX 2.1 bundle. |

Step-by-step guides: [docs/integrations.md](docs/integrations.md).

## Files
| Path | Description |
|---|---|
| `latest/` | Stable filenames, overwritten on every run |
| `archive/YYYY-MM-DD/` | Daily snapshots |
| `top-iocs.csv` | Defanged IOC, type, family, score, sources, age, context, ATT&CK |
| `blocklist-defanged.txt` | Defanged list for safe sharing |
| `fortigate-*-feed.txt`, `paloalto-edl-*.txt` | Raw values for firewall feeds |
| `sentinel-watchlist.csv`, `defender-hunt.kql` | Microsoft security stack |
| `suricata.rules` | IDS rules (SID range 9100001–9100999) |
| `stix21.json` | STIX 2.1 bundle |
| `stats.json` | Machine-readable stats (drives the badges) |

## Score scale
Every IOC gets a **score from 0 to 100** (`score` and `band` columns in the CSVs, `confidence` and a `band:` label in STIX). Only scores of 50 and above are published.

| Score | Band | Suggested action |
|---|---|---|
| 90–100 | critical | Block |
| 75–89 | high | Block |
| 50–74 | medium | Alert / hunt |

Details: [docs/methodology.md](docs/methodology.md#score-scale).

## Today's stats
_Last update: 2026-10-24 10:34 UTC. 48 IOCs (ip: 12, hash: 12, domain: 12, url: 12); 48 first seen under 6h ago._

<img src="assets/families.svg" alt="family breakdown" width="100%">

| # | IOC (defanged) | Type | Family | Score | Band | ATT&CK |
|---|---|---|---|---|---|---|
| 1 | `109[.]238[.]87[.]239` | ip | Hermes | 83 | high | T1071, T1105 |
| 2 | `167[.]148[.]201[.]108` | ip | Havoc | 83 | high | T1071, T1055 |
| 3 | `217[.]60[.]102[.]5` | ip | RedTail | 83 | high | T1071, T1105 |
| 4 | `217[.]60[.]195[.]167` | ip | Remcos | 83 | high | T1071, T1105 |
| 5 | `31[.]56[.]209[.]165` | ip | RedTail | 83 | high | T1071, T1105 |
| 6 | `89[.]32[.]41[.]111` | ip | Potassium | 83 | high | T1071, T1105 |
| 7 | `89[.]32[.]41[.]43` | ip | Potassium | 83 | high | T1071, T1105 |
| 8 | `91[.]92[.]242[.]19` | ip | Potassium | 83 | high | T1071, T1105 |
| 9 | `113[.]52[.]135[.]27` | ip | Cobaltstrike | 83 | high | T1071, T1105 |
| 10 | `114[.]215[.]184[.]158` | ip | Cobaltstrike | 83 | high | T1071, T1105 |
| 11 | `118[.]25[.]147[.]157` | ip | Cobaltstrike | 83 | high | T1071, T1105 |
| 12 | `49[.]235[.]158[.]141` | ip | Cobaltstrike | 83 | high | T1071, T1105 |
| 13 | `008391c2f5053f8d6ae93687ff3e646ea3781eb7fceb90dff27662639a78` | hash | Mirai | 74 | medium | T1071, T1105 |
| 14 | `08906e5c2a385132f3eb69000ecf18fd126ec4bb252e005f1e48ab0df144` | hash | AMOS | 74 | medium | T1071, T1105 |
| 15 | `1d32753359c4f69d692f319fb16c2aabcb940fb7e7aa5ddabc78403e4779` | hash | AMOS | 74 | medium | T1071, T1105 |

## FAQ
**How often does it update?** Every 2 hours. A commit is made only when the data changes.<br>
**Why so few entries?** On purpose. The list is tuned for blocking with a low false-positive rate.<br>
**Are the values defanged?** Only in the `top-iocs.csv` and `blocklist-defanged.txt` files. The platform files contain live values so they can be imported directly.<br>
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

## Changelog
- **2026-10-24:** scores are now on a documented 0–100 scale with bands (breaking for consumers of `score`/`confidence`); the Palo Alto URL EDL no longer contains bare IPs or trailing `/` (IP hosts moved to the IP EDLs); drop CSVs no longer start with a `#` comment line.

## Disclaimer
This feed is provided **as is**, without warranty. Indicators can go stale or produce false positives, for example on reassigned shared infrastructure. Validate before you block in production. Never browse to the listed indicators.
