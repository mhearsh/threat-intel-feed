#!/usr/bin/env python3
"""Validate feeds/ and latest/: CSV headers, no CSV starting with '#' (except Check Point's native #UNIQ-NAME header),
JSON parses, Defender <=500 rows/file, Trend <=2000 rows and <=1 MB, hash lengths, .md5 sidecars match. Exit 1 on failure."""
import csv, glob, hashlib, json, os, re, sys
R=os.path.abspath(sys.argv[1] if len(sys.argv)>1 else os.path.join(os.path.dirname(os.path.abspath(__file__)),'..')); err=[]
CPH='#UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT'
for p in glob.glob(f'{R}/feeds/**/*.csv',recursive=True)+glob.glob(f'{R}/latest/*.csv'):
    rel=os.path.relpath(p,R); first=open(p).readline().strip()
    if rel=='feeds/firewall/checkpoint/ioc-feed.csv':
        if first!=CPH: err.append(f'{rel}: bad Check Point header')
    elif first.startswith('#') or not first: err.append(f'{rel}: starts with # or empty header')
    rows=list(csv.reader(open(p)));n=len(rows)-1
    if any(len(r)!=len(rows[0]) for r in rows): err.append(f'{rel}: ragged rows')
    if 'microsoft-defender' in rel and n>500: err.append(f'{rel}: {n} rows > 500')
    if 'trendmicro' in rel and (n>2000 or os.path.getsize(p)>1_000_000): err.append(f'{rel}: over Trend limit')
for p in glob.glob(f'{R}/feeds/**/*.json',recursive=True)+glob.glob(f'{R}/latest/*.json'):
    try: json.load(open(p))
    except Exception as e: err.append(f'{os.path.relpath(p,R)}: JSON {e}')
L={'sha256':64,'sha1':40,'md5':32}
for p in glob.glob(f'{R}/feeds/**/*.txt',recursive=True):
    k=next((h for h in L if os.path.basename(p) in (f'{h}.txt',f'hash-{h}.txt')),None)
    if k and any(not re.fullmatch(f'[0-9a-f]{{{L[k]}}}',l.strip()) for l in open(p) if l.strip() and not l.startswith('#')): err.append(f'{os.path.relpath(p,R)}: bad {k}')
    if os.path.basename(p) in ('url.txt','edl-url.txt','domain.txt','edl-domain.txt') and any(l.startswith('http') for l in open(p)): err.append(f'{os.path.relpath(p,R)}: scheme present')
for p in glob.glob(f'{R}/feeds/**/*.md5',recursive=True):
    if open(p).read().strip()!=hashlib.md5(open(p[:-4],'rb').read()).hexdigest(): err.append(f'{os.path.relpath(p,R)}: checksum mismatch')
# ---- plain-text IOC lists: every non-comment line must be a valid IOC of the file's kind (refuses HTML/junk);
# titled lists need the 11-line banner with a matching Count; -plain, Cisco, Sophos and ESET files must have no '#' lines.
import listfmt as LF
def kind(b):
    b=b.replace('-plain','').replace('-titled','')
    if b.startswith('blocklist-defanged'): return 'defanged'
    for h in ('sha256','sha1','md5'):
        if h in b: return h
    if 'edl-url' in b and b.startswith('paloalto'): return 'edlurl'
    return next((k for k in ('ip','domain','url') if k in b),None)
for p in glob.glob(f'{R}/feeds/**/*.txt',recursive=True)+glob.glob(f'{R}/latest/*.txt')+glob.glob(f'{R}/reports/*.txt'):
    rel=os.path.relpath(p,R); b=os.path.basename(p); k=kind(b)
    if 'wazuh' in rel or not k: continue
    t=open(p).read(); vals=LF.values(t); titled=t.startswith('#')
    plain_only=b.endswith('-plain.txt') or (any(x in rel for x in ('/sophos/','/eset/')) and not b.endswith('-titled.txt'))
    if plain_only and '#' in ''.join(l[:1] for l in t.splitlines()): err.append(f'{rel}: comment line in a comment-free file')
    if not plain_only and t.strip() and not titled: err.append(f'{rel}: missing title banner')
    if titled:
        L11=t.splitlines()[:11]
        if len(L11)<11 or L11[0]!='#'*LF.W or L11[10]!='#'*LF.W or not re.search(rf'Count: {len(vals)}\b',t[:2000]): err.append(f'{rel}: bad banner or Count')
        hl=t.splitlines()[11:]
        if any(re.fullmatch(r'# \d{4}-\d\d-\d\d',l) and not re.fullmatch(r'# [\x20-\x7e]{1,40} / TLP:[A-Z+]+ - Threat Level: (Critical|High|Medium|Low)',hl[i-1]) for i,l in enumerate(hl) if i): err.append(f'{rel}: bad block header line 2')
        if any(l.strip()=='#' for l in t.splitlines()[11:]): err.append(f'{rel}: empty block header')
        if any(not re.fullmatch(r'# \d{4}-\d\d-\d\d',l) for l in t.splitlines()[11:] if re.match(r'# \d',l)): err.append(f'{rel}: bad block date')
    bad=[v for v in vals if not LF.valid(v,k)]
    if bad: err.append(f'{rel}: {len(bad)} invalid {k} line(s), e.g. {bad[0][:50]!r}')
    if len(vals)!=len(set(vals)): err.append(f'{rel}: duplicate values')
    if len(vals)>LF.EDL_MAX: err.append(f'{rel}: {len(vals)} > EDL cap')
# ---- structured formats: every entry carries its date of addition in a native field
D8=re.compile(r'\d{4}-\d\d-\d\d')
for p in glob.glob(f'{R}/feeds/**/*.csv',recursive=True)+glob.glob(f'{R}/latest/*.csv')+glob.glob(f'{R}/reports/*.csv'):
    rows=list(csv.DictReader(open(p))); rel=os.path.relpath(p,R)
    col=next((c for c in ('first_published','FirstPublished') if rows and c in rows[0]),None)
    dcol=next((c for c in ('Description','description','COMMENT','comment') if rows and c in rows[0]),None)
    if rows and col and any(not D8.match(r[col] or '') for r in rows): err.append(f'{rel}: bad {col}')
    elif rows and not col and dcol and any(not re.search(r'added \d{4}-\d\d-\d\d',r[dcol]) for r in rows): err.append(f'{rel}: entry without date of addition')
    elif rows and not col and not dcol and 'curated' not in rel: err.append(f'{rel}: no date-of-addition field')
for p in glob.glob(f'{R}/feeds/**/suricata.rules',recursive=True)+glob.glob(f'{R}/latest/suricata.rules'):
    t=open(p).read(); rel=os.path.relpath(p,R)
    if not t.startswith('#'*79): err.append(f'{rel}: missing banner')
    for l in t.splitlines():
        if l.strip() and not l.startswith('#') and not (l.startswith('alert ') and re.search(r'metadata:created_at \d{4}_\d\d_\d\d',l) and l.endswith(';)')): err.append(f'{rel}: bad rule line {l[:50]!r}'); break
for p in glob.glob(f'{R}/feeds/**/*.kql',recursive=True)+glob.glob(f'{R}/latest/*.kql'):
    t=open(p).read()
    if not t.startswith('//') or 'FirstPublished:datetime' not in t: err.append(f'{os.path.relpath(p,R)}: KQL header/FirstPublished missing')
for p in glob.glob(f'{R}/feeds/**/stix21*.json',recursive=True)+glob.glob(f'{R}/latest/stix21.json'):
    j=json.load(open(p)); o=j['objects'] if isinstance(j,dict) else j
    if any(x['type']=='indicator' and not D8.match(x.get('valid_from','')) for x in o): err.append(f'{os.path.relpath(p,R)}: indicator without valid_from')
    if isinstance(j,dict) and not any(x['type']=='report' for x in o): err.append(f'{os.path.relpath(p,R)}: no report/description object')
for p in glob.glob(f'{R}/feeds/siem-soar/wazuh/*.txt'):
    if any(not re.fullmatch(r'[^:#\s][^:]*:.+ added \d{4}-\d\d-\d\d',l.rstrip('\n')) for l in open(p) if l.strip()): err.append(f'{os.path.relpath(p,R)}: bad CDB line')
for p in glob.glob(f'{R}/feeds/edr/sentinelone/iocs.json'):
    if any(not re.search(r'added \d{4}-\d\d-\d\d',x['description']) for x in json.load(open(p))['data']): err.append('sentinelone: entry without date of addition')
print('\n'.join(err) or 'validate_feeds: OK'); sys.exit(1 if err else 0)
