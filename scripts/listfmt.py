#!/usr/bin/env python3
"""Plain-text IOC list format (mhearsh/list style): 11-line '#' banner, then dated blocks, newest first.
Each block: blank, '# <source/campaign>', '# TLP:<x> - Threat Level: <y>', '# YYYY-MM-DD', blank, sorted values, blank.
Values are never defanged, appear once per file, and every value is validated for the file's IOC kind."""
import ipaddress, re
W=79
TITLES={'ip':('MALICIOUS IP ADDRESSES FEED','C2 / Malware Infrastructure (threat-intel-feed)','IOC - Malicious IPv4 collection (score >= 50)','one IPv4 per line, not defanged','Firewall EDL (Palo Alto / FortiGate), SIEM'),
 'domain':('MALICIOUS DOMAINS & FQDN FEED','C2, Malware and Phishing Domains (threat-intel-feed)','IOC - Malicious domain collection (score >= 50)','one FQDN per line, not defanged','DNS filtering, web proxy, firewall EDL'),
 'url':('MALICIOUS URL FEED','Phishing / Malware Delivery URLs (threat-intel-feed)','IOC - Malicious URL collection (score >= 50)','one URL per line, no scheme, not defanged','Web proxy / firewall URL EDL'),
 'edlurl':('MALICIOUS URL & DOMAIN EDL','URLs and Domains for URL-category EDLs (threat-intel-feed)','IOC - Malicious URLs + domains (score >= 50)','one URL or FQDN per line, no scheme','Palo Alto URL EDL, web proxy'),
 'md5':('MALICIOUS FILE HASHES - MD5','Malware Samples (threat-intel-feed)','IOC - Malicious file hash collection','one MD5 (32 hex) per line','EDR / AV block lists, hunting'),
 'sha1':('MALICIOUS FILE HASHES - SHA1','Malware Samples (threat-intel-feed)','IOC - Malicious file hash collection','one SHA1 (40 hex) per line','EDR / AV block lists, hunting'),
 'sha256':('MALICIOUS FILE HASHES - SHA256','Malware Samples (threat-intel-feed)','IOC - Malicious file hash collection','one SHA256 (64 hex) per line','EDR / AV block lists, hunting')}
EDL_MAX=50000  # newest-first cap; below Palo Alto (50k IP / 100k URL per EDL) and FortiGate connector limits
HEX={'md5':32,'sha1':40,'sha256':64}
FQDN=re.compile(r'(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}',re.I)
def valid(v,kind):
    if not v or v!=v.strip() or any(c in v for c in ' \t<>"\'#') or '[.]' in v or v.lower().startswith(('http','hxxp')): return False
    if kind=='ip':
        try: return isinstance(ipaddress.ip_address(v),ipaddress.IPv4Address)
        except ValueError: return False
    if kind in HEX: return re.fullmatch(f'[0-9a-f]{{{HEX[kind]}}}',v) is not None
    if kind=='domain': return FQDN.fullmatch(v) is not None
    host=v.split('/')[0].rsplit(':',1)[0] if v.count(':')<=1 else ''
    hok=bool(FQDN.fullmatch(host)) or valid(host,'ip')
    if kind=='url': return '/' in v and hok and re.fullmatch(r'[\x21-\x7e]+',v) is not None
    if kind=='edlurl': return hok and re.fullmatch(r'[\x21-\x7e]+',v) is not None
    return False
def _row(s=''): return '#  '+s.ljust(W-4)+'#' if s else '#'+' '*(W-2)+'#'
def _ctr(s): return '#'+s.center(W-2)+'#'
def banner(kind,updated,count,expiry_days=30):
    t=TITLES[kind]; return [ '#'*W,_row(),_ctr(t[0]),_ctr(t[1]),_row(),_row('Purpose: '+t[2]),_row('Format:  '+t[3]+"; '#' = comment"),
        _row('Usage:   '+t[4]),_row(f'Updated: {updated}   Count: {count}   Expiry: {expiry_days} days'),_row(),'#'*W]
def render(kind,blocks,updated,cap=None):
    """blocks: list of (date 'YYYY-MM-DD', label, tlp_level_line, [values]). Returns (text, kept_values). Rejects invalid values."""
    seen=set(); out=[]; n=0; bad=[]
    for d,label,lvl,vals in sorted(blocks,key=lambda b:(b[0],b[1]),reverse=True):
        keep=[]
        for v in sorted(set(vals)):
            if v in seen: continue
            if not valid(v,kind): bad.append(v); continue
            if cap and n>=cap: break
            seen.add(v); keep.append(v); n+=1
        if keep: out.append((d,label,lvl,keep))
    lines=banner(kind,updated,n)+['']
    for d,label,lvl,keep in out: lines+=['',f'# {label}',f'# {lvl}',f'# {d}','']+keep+['']
    return '\n'.join(lines)+'\n',[v for b in out for v in b[3]],bad
def parse(text):
    """-> list of (date,label,lvl,[values]) from a rendered file (banner skipped)."""
    blocks=[]; hdr=[]; cur=None
    for l in text.splitlines()[11:]:
        if l.startswith('#'): hdr.append(l[2:]); cur=None
        elif l.strip():
            if cur is None:
                h=(['','','']+hdr)[-3:]; cur=(h[2],h[0],h[1],[]); blocks.append(cur); hdr=[]
            cur[3].append(l.strip())
    return blocks
def values(text): return [l.strip() for l in text.splitlines() if l.strip() and not l.startswith('#')]
