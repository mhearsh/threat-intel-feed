# Daily Drops

Each post in the **Daily Threat Intel Drop** series on X ships with a full CSV and two cards.

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
| 2026-10-25 | #2 | 50 | Unknown malware, AMOS, StrelaStealer | [CSV](2026/10/2026-10-25-drop-2.csv) | [summary](2026/10/2026-10-25-drop-2.png) · [list](2026/10/2026-10-25-drop-2-list.png) |
| 2026-10-26 | #3 | 50 | Vidar, AMOS, StrelaStealer | [CSV](2026/10/2026-10-26-drop-3.csv) | [summary](2026/10/2026-10-26-drop-3.png) · [list](2026/10/2026-10-26-drop-3-list.png) |
| 2026-10-27 | #4 | 50 | Vidar, AMOS, VShell | [CSV](2026/10/2026-10-27-drop-4.csv) | [summary](2026/10/2026-10-27-drop-4.png) · [list](2026/10/2026-10-27-drop-4-list.png) |
| 2026-10-28 | #5 | 50 | AMOS, Vidar, ClearFake | [CSV](2026/10/2026-10-28-drop-5.csv) | [summary](2026/10/2026-10-28-drop-5.png) · [list](2026/10/2026-10-28-drop-5-list.png) |
| 2026-10-29 | #6 | 50 | AMOS, XMRIG, Vidar | [CSV](2026/10/2026-10-29-drop-6.csv) | [summary](2026/10/2026-10-29-drop-6.png) · [list](2026/10/2026-10-29-drop-6-list.png) |
| 2026-10-30 | #7 | 50 | AMOS, Vidar, ClearFake | [CSV](2026/10/2026-10-30-drop-7.csv) | [summary](2026/10/2026-10-30-drop-7.png) · [list](2026/10/2026-10-30-drop-7-list.png) |
| 2026-10-31 | #8 | 50 | Unknown malware, AMOS, VShell | [CSV](2026/10/2026-10-31-drop-8.csv) | [summary](2026/10/2026-10-31-drop-8.png) · [list](2026/10/2026-10-31-drop-8-list.png) |
| 2026-11-01 | #9 | 50 | Unknown malware, AMOS, VShell | [CSV](2026/11/2026-11-01-drop-9.csv) | [summary](2026/11/2026-11-01-drop-9.png) · [list](2026/11/2026-11-01-drop-9-list.png) |
| 2026-11-02 | #10 | 50 | AMOS, Vidar, VShell | [CSV](2026/11/2026-11-02-drop-10.csv) | [summary](2026/11/2026-11-02-drop-10.png) · [list](2026/11/2026-11-02-drop-10-list.png) |
| 2026-11-03 | #11 | 50 | Vidar, AMOS, ClearFake | [CSV](2026/11/2026-11-03-drop-11.csv) | [summary](2026/11/2026-11-03-drop-11.png) · [list](2026/11/2026-11-03-drop-11-list.png) |
| 2026-11-04 | #12 | 50 | Vidar, AMOS, Remcos | [CSV](2026/11/2026-11-04-drop-12.csv) | [summary](2026/11/2026-11-04-drop-12.png) · [list](2026/11/2026-11-04-drop-12-list.png) |
| 2026-11-05 | #13 | 50 | Unknown malware, AMOS, ACR Stealer | [CSV](2026/11/2026-11-05-drop-13.csv) | [summary](2026/11/2026-11-05-drop-13.png) · [list](2026/11/2026-11-05-drop-13-list.png) |
| 2026-11-06 | #14 | 26 | phishing, multi-blocklist, Cobalt Strike | [CSV](2026/11/2026-11-06-drop-14.csv) | [summary](2026/11/2026-11-06-drop-14.png) · [list](2026/11/2026-11-06-drop-14-list.png) |
| 2026-11-07 | #15 | 26 | Cobalt Strike, phishing, Arista VCO exploitation CVE-2026-114625 | [CSV](2026/11/2026-11-07-drop-15.csv) | [summary](2026/11/2026-11-07-drop-15.png) · [list](2026/11/2026-11-07-drop-15-list.png) |
