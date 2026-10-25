# Curated indicators

Manually added indicators. **Only** indicators listed on an official source (vendor security advisory, CISA, or a national CERT) are accepted. Third-party blogs and user reports are not enough.

`curated-iocs.csv` columns: `value,type,family,cve,source_url,note,confidence,score,first_seen,expires`.
- `score` is on the feed's 0–100 scale (must be ≥ 50 to publish). 90 (critical) = vendor-confirmed active exploitation.
- Entries are dropped automatically after `expires` (UTC). IPs get about 30 days.
- The automatic runs read this file and never overwrite it. Curated entries flow into every feed format.
