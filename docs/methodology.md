# Methodology
## Pipeline
1. **Collect** every 2h: ThreatFox API (last 24h, with confidence and family), C2IntelFeeds (C2 IPs and domains), OpenPhish, IPsum level 5, Spamhaus DROP. Stale feeds are skipped automatically (for example, a feed whose header date is more than 3 days old).
2. **Normalize and dedupe** into SQLite keyed on (value, source). A value's `first_seen` is the first time any source reported it to this pipeline.
3. **Score**
   - base = highest source confidence (ThreatFox confidence_level; C2IntelFeeds 70; OpenPhish 75; IPsum 60)
   - +15 for each additional independent source
   - +15 if the IP is inside a Spamhaus DROP netblock
   - +10 for a named family or C2 framework
   - +20 if first seen < 6h ago, +10 if < 24h, −30 if > 72h
4. **Gate**: published score ≥ 50 (see below) **and** (≥ 2 sources **or** source confidence ≥ 75).
5. **Exclude**: private and reserved IPs; CDN, cloud front-end and sinkhole hostnames; stale feeds.
6. **Rank**: sort by score, then freshness. A diversity cap allows at most 12 per IOC type, up to 50 in total.
7. **Enrich**: a family context line and MITRE ATT&CK techniques from a curated mapping.
8. **Publish**: platform files, STIX 2.1, stats and charts. A commit is made only when the content changes.

## File hashes
SHA-256, SHA-1 and MD5 hashes come from ThreatFox. They are lowercased, validated (hex only; 64 / 40 / 32 characters) and de-duplicated, and keep their source, malware family and the pipeline's `first_seen`. They use the same score, bands and ≥ 50 cut-off as the other IOCs. Every passing hash is published in `sha256.txt` / `sha1.txt` / `md5.txt`, `file-hashes.csv`, the Defender (SHA-256/SHA-1) and CrowdStrike (SHA-256/MD5) import CSVs, and `stix21.json`; up to 12 hashes also appear in the top-50 list. Import actions: critical/high → block (Defender `BlockAndRemediate`, Falcon `prevent`), medium → audit/detect. Indicators expire after 30 days.

## Score scale
The raw points from step 3 are mapped to a published score: `score = clamp(round(raw × 100 / 175), 0, 100)`, where 175 is the raw maximum (100 base + 2 × 15 extra sources + 15 DROP + 10 family + 20 freshness). Ranking uses the raw points, so the order is unchanged.

| Score | Band | Suggested action |
|---|---|---|
| 90–100 | critical | Block |
| 75–89 | high | Block |
| 50–74 | medium | Alert / hunt |
| < 50 | low | Not published |

The same value appears as `score` (+ `band`) in `top-iocs.csv` and `sentinel-watchlist.csv`, and as `confidence` (+ a `band:<name>` label) in `stix21.json`. Scores before 2026-10-24 used the unbounded raw points.

## Limitations
The C2 scan feeds can contain researcher or red-team servers, and IPs can be reassigned. Treat the list as high-confidence, not as ground truth.
