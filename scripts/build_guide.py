"""Build docs/guide/GUIDE.md and IOC-Feed-Integration-Guide.pdf (needs weasyprint)."""
B="https://mhearsh.github.io/threat-intel-feed/feeds"
# (title, intro, steps, [(label,url,status)])  status: E=content exists today in latest/, N=new
S=[
("Firewalls — Palo Alto NGFW","External Dynamic Lists (pull, HTTPS).",
 ["Objects → External Dynamic Lists → Add. Create one list per type: IP, Domain, URL.","Paste the source URL below and set Repeat to Hourly.","Reference the EDL in a Security policy with action Deny or Drop.","Commit, then check List Capacities."],
 [("IP",f"{B}/firewall/paloalto/edl-ip.txt","E"),("Domain",f"{B}/firewall/paloalto/edl-domain.txt","E"),("URL",f"{B}/firewall/paloalto/edl-url.txt","E")]),
("Firewalls — Fortinet FortiGate","Security Fabric → External Connectors → Threat Feeds.",
 ["Create an IP Address, Domain Name, URL, or Malware Hash feed.","Enter the URL below. Set refresh to 60 min.","Use the feed in a firewall policy, DNS filter, web filter, or AV profile.","Use one hash algorithm per feed."],
 [("IP",f"{B}/firewall/fortinet/ip.txt","E"),("Domain",f"{B}/firewall/fortinet/domain.txt","E"),("SHA-256",f"{B}/firewall/fortinet/hash-sha256.txt","E")]),
("Firewalls — Check Point · Cisco · Sophos · pfSense","Plain-text pull feeds. Check Point uses its native CSV.",
 ["Check Point: <code>ioc_feeds add --feed_name tif --transport https --resource &lt;URL&gt;</code>, or add it in SmartConsole → Custom Intelligence Feeds.","Cisco FMC: Objects → Security Intelligence → Network/URL feed. Add the .md5 URL for intervals of 30 min or less.","Sophos XGS: Active Threat Response → Third-party threat feeds. Create one feed per type.","pfSense/OPNsense: URL Table alias or a pfBlockerNG list."],
 [("Check Point CSV",f"{B}/firewall/checkpoint/ioc-feed.csv","E"),("Generic IP",f"{B}/generic/txt/ip.txt","E"),("Generic URL",f"{B}/generic/txt/url.txt","E")]),
("EDR — Microsoft Defender for Endpoint","Settings → Endpoints → Indicators → Import. Maximum 500 rows per file. SHA-1 and SHA-256 only.",
 ["Download the file CSV below.","Select the matching tab (File hashes, or IP addresses / URLs).","Import → Choose file → Import.","Review the actions (Audit or Block) and the expiration date."],
 [("File hashes",f"{B}/edr/microsoft-defender/files-001.csv","E"),("Network",f"{B}/edr/microsoft-defender/network-001.csv","E")]),
("EDR — CrowdStrike · SentinelOne · ESET","Import through the API, or paste the hashes.",
 ["CrowdStrike: import the CSV with FalconPy or PSFalcon (IOC API).","SentinelOne: POST the JSON to /web/api/v2.1/threat-intelligence/iocs.","ESET PROTECT: Blocked hashes → Add hashes. Paste the SHA-256 or SHA-1 list."],
 [("CrowdStrike",f"{B}/edr/crowdstrike/iocs-api.csv","E"),("SentinelOne",f"{B}/edr/sentinelone/iocs.json","E"),("ESET SHA-256",f"{B}/edr/eset/sha256.txt","E")]),
("EDR — Trend Vision One · Cortex XDR","CSV import.",
 ["Trend: Threat Intelligence → Suspicious Object Management → Import (max 2,000 objects / 1 MB).","Cortex XDR: Detection Rules → IOC → Import CSV."],
 [("Trend Vision One",f"{B}/edr/trendmicro/suspicious-objects.csv","E"),("Cortex XDR",f"{B}/edr/cortex-xdr/iocs.csv","E")]),
("SIEM / SOAR","STIX 2.1 for TI platforms. Typed CSV for Splunk.",
 ["Microsoft Sentinel: Threat intelligence → Import → JSON (STIX).","Splunk ES: Threat intelligence → Data sources → URL. Use the ip_intel and file_intel CSVs.","MISP / OpenCTI / XSOAR: add the STIX file or the generic CSV as a feed.","QRadar / Wazuh: load the generic txt into a reference set or CDB list."],
 [("STIX 2.1",f"{B}/generic/stix/stix21.json","E"),("Splunk ip_intel",f"{B}/siem-soar/splunk/ip_intel.csv","E"),("Generic CSV",f"{B}/generic/csv/iocs.csv","E")]),
]
md=["# IOC Feed Integration Guide","_Open threat-intel feed · github.com/mhearsh/threat-intel-feed_","","Scores 0–100: **Critical 90–100 · High 75–89 · Medium 50–74**. Feeds refresh every 2 hours. Entries expire after 30 days.","","> ● = available now. Raw fallback: `https://raw.githubusercontent.com/mhearsh/threat-intel-feed/main/feeds/...`. Legacy `latest/` paths stay online as a compatibility mirror.",""]
html=[]
for t,i,st,urls in S:
    md+= [f"## {t}",i,""]+[f"{n}. {s.replace('<code>','`').replace('</code>','`').replace('&lt;','<').replace('&gt;','>')}" for n,s in enumerate(st,1)]+[""]+[f"- {'●' if s=='E' else '○'} **{l}:** `{u}`" for l,u,s in urls]+[""]
    lis="".join(f"<li>{s}</li>" for s in st)
    us="".join(f"<tr><td class='st {s}'>{'●' if s=='E' else '○'}</td><td class='l'>{l}</td><td><code>{u.replace(B,'…/feeds')}</code></td></tr>" for l,u,s in urls)
    html.append(f"<section><h2>{t}</h2><p class='i'>{i}</p><ol>{lis}</ol><table>{us}</table></section>")
sig="Eliran Emuna — Cyber Security"
md+=["---","","**"+sig+"**  ","Threat Intelligence Feed · 2026"]
import os;os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","docs","guide"))
open("GUIDE.md","w").write("\n".join(md))
css="""@page{size:A4;margin:16mm 16mm 18mm;@bottom-center{content:"IOC Feed Integration Guide · "counter(page);font:8pt Helvetica;color:#7a8ba6}}
body{font-family:Helvetica,Arial,sans-serif;color:#1b2536;font-size:10pt;margin:0}
.cover{background:#0b1a33;color:#fff;padding:20px 24px;border-radius:6px;border-left:6px solid #19d3e6;margin-bottom:14px}
.cover h1{margin:0;font-size:22pt;letter-spacing:.5px}.cover p{margin:6px 0 0;color:#9fdfe8;font-size:9.5pt}
.bands span{display:inline-block;padding:2px 8px;border-radius:10px;margin-right:6px;font-size:8.5pt;color:#fff}
section{border:1px solid #d6dde8;border-radius:6px;padding:10px 14px;margin:0 0 10px;page-break-inside:avoid}
h2{margin:0 0 4px;font-size:12.5pt;color:#0b1a33;border-bottom:2px solid #19d3e6;padding-bottom:3px}
.i{margin:4px 0;color:#4a5a73;font-size:9pt}ol{margin:4px 0 6px 18px;padding:0}li{margin:2px 0}
table{width:100%;border-collapse:collapse;font-size:8.3pt}td{padding:3px 4px;border-top:1px solid #edf1f6}
td.l{font-weight:bold;width:110px;color:#0b1a33}.st{width:12px}.E{color:#0aa5b8}.N{color:#9aa6b8}
code{font-family:Courier,monospace;font-size:8pt;color:#0b5f6b}
.note{font-size:8.5pt;color:#4a5a73;margin:0 0 10px}
.sig{margin-top:18px;border-top:2px solid #0b1a33;padding-top:8px;page-break-inside:avoid}
.sig .n{font-size:14pt;font-weight:bold;color:#0b1a33;font-family:Georgia,serif;font-style:italic}.sig .r{color:#19a3b5;font-size:9pt;letter-spacing:1px;text-transform:uppercase}"""
doc=f"""<html><head><meta charset=utf-8><style>{css}</style></head><body>
<div class=cover><h1>IOC Feed Integration Guide</h1><p>Open threat-intelligence feed · Firewalls · EDR/XDR · SIEM/SOAR</p>
<p class=bands style="margin-top:10px"><span style="background:#c0263b">Critical 90–100</span><span style="background:#e07b16">High 75–89</span><span style="background:#2f7fd1">Medium 50–74</span></p></div>
<p class=note>Base URL: <code>{B}</code> · Refresh: every 2 h · Expiry: 30 days · ● available now. Legacy <code>latest/</code> URLs remain as a compatibility mirror.</p>
{''.join(html)}
<div class=sig><div class=n>Eliran Emuna</div><div class=r>Cyber Security</div><div style="font-size:8.5pt;color:#4a5a73;margin-top:4px">Threat Intelligence Feed · github.com/mhearsh/threat-intel-feed · 2026</div></div></body></html>"""
import weasyprint;weasyprint.HTML(string=doc).write_pdf("IOC-Feed-Integration-Guide.pdf")
