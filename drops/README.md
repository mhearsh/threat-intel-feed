# Daily Drops

Each post in the **Daily Threat Intel Drop** series on X ([@EmunaEliran](https://x.com/EmunaEliran)) ships with a full CSV and two cards.

## Layout
`drops/YYYY/MM/YYYY-MM-DD-drop-N.csv` · `...-drop-N.png` (summary card) · `...-drop-N-list.png` (full list card)

## CSV format
Line 1 is the header row (no comment lines), so the file imports directly into any CSV tool.

| Column | Description |
|---|---|
| `indicator` | Raw value, ready for import into blocklists / SIEM. **Live indicator, handle with care.** |
| `indicator_defanged` | Safe-to-share form (`[.]`, `hxxp`) |
| `type` | `ip`, `domain`, `url` or `hash` (SHA-256) |
| `family` | Malware family (`Hermes (malware)` is a malware family, unrelated to any AI agent) |
| `confidence` | Score 0–100 (critical ≥ 90, high 75–89, medium 50–74; see [methodology](../docs/methodology.md#score-scale)). Drops published before 2026-10-24 used the older unbounded internal score |
| `first_seen` | First-seen time (UTC) |
| `tags` | Family, type and MITRE ATT&CK technique IDs, `;`-separated |

License: see [LICENSE](../LICENSE).

## Index

| Date | Drop | IOCs | Top families | CSV | Cards |
|---|---|---|---|---|---|
| 2026-10-24 | #1 | 48 | AMOS, ClearFake, RedTail | [CSV](2026/10/2026-10-24-drop-1.csv) | [summary](2026/10/2026-10-24-drop-1.png) · [list](2026/10/2026-10-24-drop-1-list.png) |
