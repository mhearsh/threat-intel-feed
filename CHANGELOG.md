# Changelog

## 2026-10-24
- **New `feeds/` layout**: `feeds/generic/{txt,csv,stix}`, `feeds/firewall/<vendor>`, `feeds/edr/<vendor>`, `feeds/siem-soar/<vendor>`; human-readable files in `reports/`. `latest/` is kept as a compatibility mirror with the original filenames.
- **GitHub Pages now serves the feeds** (`/feeds/…` and `/latest/…`) via a GitHub Actions deployment, alongside `docs/`.
- New outputs: separate `url.txt` / `domain.txt`, `.md5` checksum files (Cisco FMC), Check Point native CSV, Trend Vision One suspicious objects, Cortex XDR, SentinelOne IOC API JSON, Splunk ES `ip_intel` / `file_intel` / `http_intel`, Wazuh CDB lists, generic non-defanged `iocs.csv`.
- Microsoft Defender indicators split into ≤500-row files, file hashes separate from network indicators.
- `crowdstrike/iocs-api.csv` documented as an IOC API helper (no native Falcon CSV import).
- Integration guide added: `docs/guide/` (Markdown + PDF).
- `scripts/validate_feeds.py` runs before every commit.
- File-hash feed (SHA-256 / SHA-1 / MD5, Defender and CrowdStrike CSVs, STIX `file:hashes`).
- **Breaking:** scores moved to a 0–100 scale with bands (critical 90–100, high 75–89, medium 50–74). Only scores ≥ 50 are published.
