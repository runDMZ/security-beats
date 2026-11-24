#!/usr/bin/env python3
"""
hash_crack.py — cassage hors-ligne de hashs non salés par dictionnaire.
Lit un fichier de hashs (un par ligne) et une wordlist, retrouve les
mots de passe. L'algorithme est auto-détecté d'après la longueur du
hash, ou forcé avec -a.

Usage:
  hash_crack.py -H hashes.txt -w rockyou.txt
  hash_crack.py -H hashes.txt -w rockyou.txt -a sha256
"""
import argparse, hashlib, sys

BY_LEN = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-H", "--hashes", required=True, help="fichier de hashs (un par ligne)")
    ap.add_argument("-w", "--wordlist", required=True)
    ap.add_argument("-a", "--algo", choices=sorted(hashlib.algorithms_guaranteed),
                    help="forcer l'algo (sinon auto-détecté par longueur)")
    a = ap.parse_args()

    targets = {}
    for line in open(a.hashes):
        h = line.strip().lower()
        if not h:
            continue
        algo = a.algo or BY_LEN.get(len(h))
        if not algo:
            print(f"[!] longueur inconnue, algo indéterminé: {h}", file=sys.stderr); continue
        targets.setdefault(algo, {})[h] = None

    total = sum(len(v) for v in targets.values())
    remaining = total
    with open(a.wordlist, "rb") as f:
        for raw in f:
            pw = raw.rstrip(b"\n")
            for algo, d in targets.items():
                if remaining == 0:
                    break
                digest = hashlib.new(algo, pw).hexdigest()
                if digest in d and d[digest] is None:
                    d[digest] = pw.decode("latin-1")
                    remaining -= 1
            if remaining == 0:
                break

    for algo, d in targets.items():
        for h, pw in d.items():
            print(f"{algo}:{h} -> {pw if pw is not None else '(non trouvé)'}")
    print(f"\n[{total-remaining}/{total} cassés]", file=sys.stderr)

if __name__ == "__main__":
    main()
