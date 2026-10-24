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
    if k and any(not re.fullmatch(f'[0-9a-f]{{{L[k]}}}',l.strip()) for l in open(p) if l.strip()): err.append(f'{os.path.relpath(p,R)}: bad {k}')
    if os.path.basename(p) in ('url.txt','edl-url.txt','domain.txt','edl-domain.txt') and any(l.startswith('http') for l in open(p)): err.append(f'{os.path.relpath(p,R)}: scheme present')
for p in glob.glob(f'{R}/feeds/**/*.md5',recursive=True):
    if open(p).read().strip()!=hashlib.md5(open(p[:-4],'rb').read()).hexdigest(): err.append(f'{os.path.relpath(p,R)}: checksum mismatch')
print('\n'.join(err) or 'validate_feeds: OK'); sys.exit(1 if err else 0)
