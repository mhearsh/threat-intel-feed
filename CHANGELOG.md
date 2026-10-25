# Changelog
All notable changes to this feed. Dates are UTC.

## [Unreleased] — 2026-10-25
### Fixed (format validation)
- **Microsoft Sentinel / STIX:** all STIX timestamps now have millisecond precision (`…:50.000Z`), so every object passes STIX 2.1 validation. New `feeds/siem-soar/microsoft-sentinel/stix21-objects.json`: a top-level array of STIX objects matching Sentinel's *Import using a file* JSON template. The bundle `stix21.json` is unchanged in structure.
- **Splunk ES:** `http_intel.csv` now has the documented header `description,http_referrer,http_user_agent,url,weight`; `ip_intel.csv` uses `description,ip,weight`; domains moved to the new `domain_intel.csv` (`description,domain,weight`).
- **Check Point:** `ioc-feed.csv` now exports SHA1 and SHA256 hashes (PRODUCT AV) in addition to MD5.

## [1.0.0] — 2026-10-24
First tagged release. Integration guide: https://mhearsh.github.io/threat-intel-feed/guide/IOC-Feed-Integration-Guide.pdf

### Layout and delivery
- **New `feeds/` layout**: `feeds/generic/{txt,csv,stix}`, `feeds/firewall/<vendor>`, `feeds/edr/<vendor>`, `feeds/siem-soar/<vendor>`; human-readable files in `reports/`. `latest/` is kept as a compatibility mirror with the original filenames.
- **GitHub Pages now serves the feeds** (`/feeds/…` and `/latest/…`) via a GitHub Actions deployment, alongside `docs/`.
- New outputs: separate `url.txt` / `domain.txt`, `.md5` checksum files (Cisco FMC), Check Point native CSV, Trend Vision One suspicious objects, Cortex XDR, SentinelOne IOC API JSON, Splunk ES `ip_intel` / `file_intel` / `http_intel`, Wazuh CDB lists, generic non-defanged `iocs.csv`.
- Microsoft Defender indicators split into ≤500-row files, file hashes separate from network indicators.
- `crowdstrike/iocs-api.csv` documented as an IOC API helper (no native Falcon CSV import).
- Integration guide added: `docs/guide/` (Markdown + PDF).
- `scripts/validate_feeds.py` runs before every commit.

### Hash feed
- File-hash feed (SHA-256 / SHA-1 / MD5, Defender and CrowdStrike CSVs, STIX `file:hashes`).

### Quality fixes and score scale
- **Breaking:** scores moved to a 0–100 scale with bands (critical 90–100, high 75–89, medium 50–74). Only scores ≥ 50 are published.
- Palo Alto URL EDL cleaned: no `http(s)://` scheme, no trailing `/`; bare IPs and the host IPs of IP-hosted URLs moved to the IP lists.
- CSV files never start with a `#` comment line (guard in the publish step).
- README badges rendered as HTML so they display correctly on GitHub.
- Commits limited to at most one feed update every ~2 hours.
