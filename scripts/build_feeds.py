#!/usr/bin/env python3
"""Build feeds/** (generic + per-vendor) and reports/ from latest/ (the compat mirror written by the collector).
Only indicators with score >= 50 (0-100 scale) are published. Usage: build_feeds.py [repo_root]"""
import csv, datetime as dt, hashlib, json, os, shutil, sys
R=os.path.abspath(sys.argv[1] if len(sys.argv)>1 else os.path.join(os.path.dirname(os.path.abspath(__file__)),'..'))
L=os.path.join(R,'latest'); F=os.path.join(R,'feeds')
def rd(n):
    p=os.path.join(L,n); return [l.strip() for l in open(p) if l.strip() and not l.startswith('#')] if os.path.exists(p) else []
rows=[r for r in csv.DictReader(open(os.path.join(L,'iocs.csv'))) if int(r['score'])>=50]
net=[r for r in rows if r['type'] in ('ip','domain','url')]; hs=[r for r in rows if r['type'] in ('md5','sha1','sha256')]
now=dt.datetime.now(dt.timezone.utc); exp=now+dt.timedelta(days=30)
EXP_ISO=exp.strftime('%Y-%m-%dT%H:%M:%SZ'); EXP_MS=int(exp.timestamp()*1000)
fpd=lambda r:(r.get('first_published') or r.get('first_seen') or now.strftime('%Y-%m-%d'))[:10]  # date of addition
desc=lambda r:f"{r['family'] or 'malicious'} score {r['score']} ({r['band']}) added {fpd(r)}"
if os.path.isdir(F): shutil.rmtree(F)
def out(rel,data):
    p=os.path.join(F,rel); os.makedirs(os.path.dirname(p),exist_ok=True)
    open(p,'w',newline='').write(data); return p
def txt(rel,vals,md5=False):
    p=out(rel,''.join(v+'\n' for v in vals))
    if md5: open(p+'.md5','w').write(hashlib.md5(open(p,'rb').read()).hexdigest()+'\n')
def csvf(rel,header,data):
    p=os.path.join(F,rel); os.makedirs(os.path.dirname(p),exist_ok=True)
    with open(p,'w',newline='') as f: w=csv.writer(f,lineterminator='\n'); w.writerow(header); w.writerows(data)
def cp(src,rel):
    s=os.path.join(L,src)
    if os.path.exists(s): os.makedirs(os.path.dirname(os.path.join(F,rel)),exist_ok=True); shutil.copy(s,os.path.join(F,rel))
import listfmt as LF
_upd=now.strftime('%Y-%m-%d %H:%M UTC')
def blk(n):  # dated blocks from latest/<n> (falls back to one block for a legacy plain file)
    p=os.path.join(L,n); t=open(p).read() if os.path.exists(p) else ''
    return LF.parse(t) if t.startswith('#') else [(now.strftime('%Y-%m-%d'),'Auto-Fetch-ThreatIntel','Malicious indicators / TLP:CLEAR - Threat Level: High',LF.values(t))]
def btxt(rel,kind,src,md5=False,plain=False):  # titled list (+ optional comment-free -plain copy); invalid lines are refused
    data,kept,bad=LF.render(kind,blk(src),_upd,LF.EDL_MAX)
    if bad: print('build_feeds: rejected',rel,len(bad))
    p=out(rel,data)
    if md5: open(p+'.md5','w').write(hashlib.md5(open(p,'rb').read()).hexdigest()+'\n')
    if plain: txt(rel[:-4]+'-plain.txt',kept,md5=md5)
def chunks(xs,n): return [xs[i:i+n] for i in range(0,len(xs),n)] or [[]]
ip,dom,url=rd('ip.txt'),rd('domain.txt'),rd('url.txt'); H={h:rd(f'{h}.txt') for h in ('sha256','sha1','md5')}
# ---- generic
for n in ('ip','domain','url','sha256','sha1','md5'): btxt(f'generic/txt/{n}.txt',n,f'{n}.txt',md5=True)
import re as _re
_sp=os.path.join(L,'stix21.json')
if os.path.exists(_sp):  # STIX 2.1 requires millisecond precision on timestamps
    _b=json.load(open(_sp)); _ms=lambda v:_re.sub(r'(T\d\d:\d\d:\d\d)Z$',r'\1.000Z',v) if isinstance(v,str) else v
    for _o in _b['objects']:
        for _k in ('created','modified','valid_from','valid_until'):
            if _k in _o: _o[_k]=_ms(_o[_k])
    json.dump(_b,open(_sp,'w'),indent=1)
cp('iocs.csv','generic/csv/iocs.csv'); cp('file-hashes.csv','generic/csv/file-hashes.csv'); cp('stix21.json','generic/stix/stix21.json')
# ---- firewalls
for n,k in (('ip','ip'),('domain','domain'),('url','url')): btxt(f'firewall/paloalto/edl-{n}.txt',k,f'{n}.txt',plain=True); btxt(f'firewall/fortinet/{n}.txt',k,f'{n}.txt',plain=True)
for h in H: btxt(f'firewall/fortinet/hash-{h}.txt',h,f'{h}.txt',plain=True)
# Cisco, Sophos, ESET, Wazuh stay comment-free (comment support not confirmed)
CPT={'ip':'IP','domain':'Domain','url':'URL','md5':'MD5','sha1':'SHA1','sha256':'SHA256'}; cpl=[]; k={}
for r in net+hs:  # Check Point: hashes (MD5/SHA1/SHA256) -> AV; network -> AB
    k[r['type']]=k.get(r['type'],0)+1; b=r['band']
    cpl.append([f"tif-{r['type']}-{k[r['type']]}",r['value'],CPT[r['type']],b,b,'AV' if r['type'] in ('md5','sha1','sha256') else 'AB',desc(r).replace(',',' ')])
csvf('firewall/checkpoint/ioc-feed.csv',['#UNIQ-NAME','VALUE','TYPE','CONFIDENCE','SEVERITY','PRODUCT','COMMENT'],cpl)
for n in ('ip','domain','url'): btxt(f'firewall/cisco/{n}.txt',n,f'{n}.txt',md5=True)  # FMC: '#' lines are comments (docs.manage.security.cisco.com r_custom-list-and-feed-requirements)
txt('firewall/sophos/ip.txt',ip); txt('firewall/sophos/domain.txt',dom); txt('firewall/sophos/url.txt',url)  # Sophos third-party feeds: one IOC per line, no comments
for n in ('ip','domain','url'): btxt(f'firewall/sophos/{n}-titled.txt',n,f'{n}.txt')  # human/titled sibling, do not point Sophos at it
cp('suricata.rules','firewall/suricata/suricata.rules')
# ---- EDR
DH=['IndicatorType','IndicatorValue','ExpirationTime','Action','Severity','Title','Description','RecommendedActions','RbacGroups','Category','MitreTechniques','GenerateAlert']
dfile=[l for l in csv.reader(open(os.path.join(L,'defender-indicators.csv')))][1:] if os.path.exists(os.path.join(L,'defender-indicators.csv')) else []
for i,c in enumerate(chunks(dfile,500),1): csvf(f'edr/microsoft-defender/files-{i:03d}.csv',DH,c)
DT={'ip':'IpAddress','domain':'DomainName','url':'Url'}; hi=lambda r:r['band'] in ('critical','high')
dnet=[[DT[r['type']],r['value'],EXP_ISO,'Block' if hi(r) else 'Audit','High' if hi(r) else 'Medium',f"threat-intel-feed: {r['family'] or 'malicious'}",desc(r)+f" | sources: {r['sources'].replace('|',',')}",'Investigate devices that contacted this indicator','','CommandAndControl' if r['type']=='ip' else 'Malware','','True'] for r in net]
for i,c in enumerate(chunks(dnet,500),1): csvf(f'edr/microsoft-defender/network-{i:03d}.csv',DH,c)
cp('defender-hunt.kql','edr/microsoft-defender/hunt.kql')
cp('crowdstrike-iocs.csv','edr/crowdstrike/iocs-api.csv')
out('edr/crowdstrike/README.md',"# CrowdStrike Falcon: API helper\n\n`iocs-api.csv` is **not** a native Falcon CSV import format (none is documented). Its columns map 1:1 to the IOC API fields of `POST /iocs/entities/indicators/v1` (type, value, action, platforms, severity, description, source, expiration, applied_globally). Load it with FalconPy or PSFalcon.\n")
ST={'ip':'IPV4','domain':'DNS','url':'URL','md5':'MD5','sha1':'SHA1','sha256':'SHA256'}
s1=[{'source':'threat-intel-feed','type':ST[r['type']],'value':r['value'],'method':'EQUALS','validUntil':EXP_ISO,'name':f"{r['family'] or 'malicious'} {r['type']}",'description':desc(r),'externalId':r['value'],'severity':{'critical':5,'high':4,'medium':3}.get(r['band'],3)} for r in rows]
out('edr/sentinelone/iocs.json',json.dumps({'data':s1},indent=1))
out('edr/sentinelone/README.md',"# SentinelOne\n\n`iocs.json` is a ready-to-POST body for `POST /web/api/v2.1/threat-intelligence/iocs`. Add your own `filter` scope (account/site) before posting. validUntil is 30 days.\n")
txt('edr/eset/sha256.txt',H['sha256']); txt('edr/eset/sha1.txt',H['sha1'])  # ESET: no documented comment support -> plain
for h in ('sha256','sha1'): btxt(f'edr/eset/{h}-titled.txt',h,f'{h}.txt')
TT={'ip':'IP','domain':'Domain','url':'URL','sha1':'File SHA-1','sha256':'File SHA-256'}
tl=[[TT[r['type']],r['value'],desc(r)] for r in rows if r['type'] in TT]
for i,c in enumerate(chunks(tl,2000),1): csvf('edr/trendmicro/suspicious-objects.csv' if i==1 else f'edr/trendmicro/suspicious-objects-{i:03d}.csv',['Type','Object','Description'],c)
XT={'ip':'IP','domain':'DOMAIN_NAME','sha256':'HASH'}
csvf('edr/cortex-xdr/iocs.csv',['indicator','type','severity','expiration_date','comment','reputation','reliability'],[[r['value'],XT[r['type']],r['band'].upper(),EXP_MS,desc(r),'BAD','C'] for r in rows if r['type'] in XT])
# ---- SIEM / SOAR
cp('stix21.json','siem-soar/microsoft-sentinel/stix21.json'); out('siem-soar/microsoft-sentinel/stix21-objects.json',json.dumps([o for o in json.load(open(_sp))['objects'] if o['type']!='report'],indent=1)) if os.path.exists(_sp) else None; cp('sentinel-watchlist.csv','siem-soar/microsoft-sentinel/watchlist.csv')
W={'critical':3,'high':2,'medium':1}
csvf('siem-soar/splunk/ip_intel.csv',['description','ip','weight','first_published'],[[desc(r),r['value'],W[r['band']],fpd(r)] for r in net if r['type']=='ip'])
csvf('siem-soar/splunk/domain_intel.csv',['description','domain','weight','first_published'],[[desc(r),r['value'],W[r['band']],fpd(r)] for r in net if r['type']=='domain'])
csvf('siem-soar/splunk/file_intel.csv',['description','file_hash','file_name','weight','first_published'],[[desc(r),r['value'],'',W[r['band']],fpd(r)] for r in hs])
csvf('siem-soar/splunk/http_intel.csv',['description','http_referrer','http_user_agent','url','weight','first_published'],[[desc(r),'','',r['value'],W[r['band']],fpd(r)] for r in net if r['type']=='url'])
cdb=lambda xs:[f'{r["value"]}:{(r["family"] or "malicious").replace(":"," ")} added {fpd(r)}' for r in xs]  # Wazuh CDB key:value, no comments
txt('siem-soar/wazuh/cdb-ip.txt',cdb([r for r in net if r['type']=='ip'])); txt('siem-soar/wazuh/cdb-domain.txt',cdb([r for r in net if r['type']=='domain'])); txt('siem-soar/wazuh/cdb-sha256.txt',cdb([r for r in hs if r['type']=='sha256']))
# ---- reports (human-readable, defanged) + compat note
os.makedirs(os.path.join(R,'reports'),exist_ok=True)
for n in ('top-iocs.csv','blocklist-defanged.txt'):
    if os.path.exists(os.path.join(L,n)): shutil.copy(os.path.join(L,n),os.path.join(R,'reports',n))
open(os.path.join(L,'README.md'),'w').write("# latest/ (compatibility mirror)\n\nSame filenames and content as before; kept online permanently. New integrations should use `feeds/` (see docs/guide/GUIDE.md).\n")
json.dump({'generated':now.strftime('%Y-%m-%dT%H:%M:%SZ'),'score_min':50,'counts':{t:sum(1 for r in rows if r['type']==t) for t in ST}},open(os.path.join(F,'metadata.json'),'w'),indent=1)
print('feeds built:',sum(len(f) for _,_,f in os.walk(F)),'files')
# ---- Pages home (docs/index.html): every feed file + guide
import html as _h
D=os.path.join(R,'docs'); os.makedirs(D,exist_ok=True); grp={}
for dp,_,fs in os.walk(F):
    for f in fs: rel=os.path.relpath(os.path.join(dp,f),R); grp.setdefault(os.path.dirname(rel),[]).append(rel)
sec=''.join(f"<h3>{_h.escape(g)}/</h3><ul>"+''.join(f'<li><a href="{_h.escape(x)}">{_h.escape(os.path.basename(x))}</a></li>' for x in sorted(grp[g]))+"</ul>" for g in sorted(grp))
leg=''.join(f'<li><a href="latest/{n}">{n}</a></li>' for n in sorted(os.listdir(L)))
open(os.path.join(D,'index.html'),'w').write(f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>threat-intel-feed</title>
<style>body{{font-family:Segoe UI,Helvetica,Arial,sans-serif;max-width:960px;margin:auto;padding:24px;color:#1b2536}}h1{{margin-bottom:4px}}.hero{{background:#0b1a33;color:#fff;padding:18px 22px;border-radius:8px;border-left:6px solid #19d3e6}}.hero a{{color:#7ff7ee}}h3{{margin:18px 0 4px;font-size:15px;color:#0b1a33;border-bottom:1px solid #d6dde8}}ul{{columns:2;margin:4px 0}}li{{font-family:Consolas,monospace;font-size:13px}}a{{color:#0b5f6b}}.b span{{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px;margin-right:6px}}</style></head><body>
<div class=hero><h1>threat-intel-feed</h1><p>Curated, high-confidence IOCs (IPs, domains, URLs, file hashes) in ready-to-import formats for firewalls, EDR/XDR and SIEM/SOAR. Updated every 2 hours · last build {now.strftime('%Y-%m-%d %H:%M UTC')}.</p>
<p class=b><span style="background:#c0263b">critical 90–100</span><span style="background:#e07b16">high 75–89</span><span style="background:#2f7fd1">medium 50–74</span></p>
<p><b>📘 <a href="guide/IOC-Feed-Integration-Guide.pdf">Integration guide (PDF)</a> · <a href="guide/GUIDE.md">Markdown</a></b> · <a href="https://github.com/mhearsh/threat-intel-feed">GitHub repo</a> · <a href="https://github.com/mhearsh/threat-intel-feed/blob/main/CHANGELOG.md">Changelog</a></p></div>
<h2>Feeds</h2>{sec}<h2>Legacy paths (latest/, compatibility mirror)</h2><ul>{leg}</ul></body></html>""")
open(os.path.join(F,'index.html'),'w').write('<!doctype html><meta charset=utf-8><meta http-equiv="refresh" content="0; url=../"><title>feeds</title><a href="../">Feed index</a>\n')
