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
4. **Gate**: score ≥ 85 **and** (≥ 2 sources **or** source confidence ≥ 75).
5. **Exclude**: private and reserved IPs; CDN, cloud front-end and sinkhole hostnames; stale feeds.
6. **Rank**: sort by score, then freshness. A diversity cap allows at most 12 per IOC type, up to 50 in total.
7. **Enrich**: a family context line and MITRE ATT&CK techniques from a curated mapping.
8. **Publish**: platform files, STIX 2.1, stats and charts. A commit is made only when the content changes.

## Limitations
The C2 scan feeds can contain researcher or red-team servers, and IPs can be reassigned. Treat the list as high-confidence, not as ground truth.
