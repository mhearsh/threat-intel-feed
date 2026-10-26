# Integration guides

> **New:** the full per-vendor guide with Pages URLs is at [guide/GUIDE.md](guide/GUIDE.md) ([PDF](guide/IOC-Feed-Integration-Guide.pdf)). The `latest/` URLs below keep working (compatibility mirror).
## List format (.txt)
Generic, Palo Alto and FortiGate `.txt` lists start with an 11-line `#` title banner (with `Updated`, `Count`, `Expiry: 30 days`), followed by dated blocks, newest first:
```
# Auto-Fetch-ThreatIntel: Spamhaus-DROP + ThreatFox
# TLP:CLEAR - Threat Level: High
# 2026-10-26

94.154.43.195
```
The date is when the IOC first entered the feed. Palo Alto EDLs and FortiGate threat feeds ignore `#` lines. If your parser does not, use the `-plain.txt` file next to it (e.g. `paloalto/edl-ip-plain.txt`, `fortinet/ip-plain.txt`, `latest/paloalto-edl-ip-plain.txt`). Cisco FMC lists are titled too (FMC treats `#` lines as comments). Sophos and ESET keep comment-free files at the same paths, with `-titled.txt` copies for reading. Wazuh CDB stays `key:value`. Structured files carry the date of addition natively: `first_published` CSV columns or `added YYYY-MM-DD` in description fields, STIX `created`/`valid_from` plus a `report` object, Suricata `metadata:created_at`, and a `FirstPublished` column in the KQL datatable.

## FortiGate (FortiOS 7.x)
1. *Security Fabric → External Connectors → Create New → Threat Feeds → IP Address*.
2. Name: `TIF-IP`. URI: `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/fortigate-ip-feed.txt`. Refresh rate: 60 min. Click OK, then *View Entries* to verify.
3. *Policy & Objects → Firewall Policy*: create a policy from LAN to WAN with destination `TIF-IP` and action DENY, logging on. Add the reverse direction (WAN→LAN, source `TIF-IP`) on inbound policies.
4. Domains: create a *Domain Name* threat feed with `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/fortigate-domain-feed.txt`. In *Security Profiles → DNS Filter → FortiGuard category based filter → Remote Categories*, set it to Block.
CLI:
```
config system external-resource
  edit "TIF-IP"
    set type address
    set resource "https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/fortigate-ip-feed.txt"
    set refresh-rate 60
  next
end
```
## Palo Alto (PAN-OS 10+)
1. *Objects → External Dynamic Lists → Add*. Type *IP List*, source `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/paloalto-edl-ip.txt`, check every hour.
2. Add another with type *URL List* and source `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/paloalto-edl-url.txt`.
3. Use the IP EDL as the destination in a deny security rule (and as the source in an inbound rule). Add the URL EDL to a URL Filtering profile with action block. Commit.
## Microsoft Sentinel
*Watchlists → + New*. Source: local file `sentinel-watchlist.csv`, SearchKey `Indicator`. Example query:
```kql
let tif = _GetWatchlist('TIF') | project Indicator;
CommonSecurityLog | where DestinationIP in (tif)
```
To keep it fresh, automate the watchlist update with a Logic App that fetches the raw CSV every 2h.
## Defender XDR
Run `defender-hunt.kql` in *Hunting → Advanced hunting*, and save it as a custom detection rule that runs every hour.
## Suricata
```
suricata-update add-source tif https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/latest/suricata.rules
suricata-update && suricatasc -c reload-rules
```
## STIX 2.1 / MISP / OpenCTI
- **MISP**: *Event Actions → Import from… → STIX 2.x*, or add it as a feed of type freetext/STIX.
- **OpenCTI**: use the *import-file-stix* connector, or poll the raw URL.
- **TAXII**: serve `stix21.json` from your TAXII 2.1 server (for example, medallion) as a collection.
