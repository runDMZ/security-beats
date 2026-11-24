# 🥁 Cracking

Offline password-recovery helpers. Small, readable tools to understand *how* a hash falls — not a replacement for the heavy artillery.

| Script | What it does | Input |
|---|---|---|
| [`hash_crack.py`](hash_crack.py) | Cracks **unsalted** hashes by dictionary. Auto-detects the algorithm from the hash length (MD5, SHA-1, SHA-256, SHA-512), cracks a whole list in a single wordlist pass | a file of hashes + a wordlist |

## Why unsalted hashes fall

A plain hash like `MD5(password)` has two fatal properties for password storage:

- **Fast** — billions of guesses per second on commodity hardware, so a dictionary runs in seconds.
- **Unsalted** — the same password always gives the same hash. Two users sharing `5f4dcc3b5aa765d61d8327deb882cf99` have the *same* password, visible before you crack a thing, and precomputed rainbow tables apply directly.

The fix is a **slow, salted** password hash — `bcrypt`, `argon2`, `scrypt`. The per-user salt kills rainbow tables and hides shared passwords; the slowness makes brute force expensive.

## Usage

```bash
# Algorithm auto-detected from hash length
./hash_crack.py -H hashes.txt -w /path/to/rockyou.txt

# Or force it
./hash_crack.py -H hashes.txt -w rockyou.txt -a sha256
```

`hashes.txt` holds one hex hash per line. Output is `algo:hash -> password`, with a cracked/total count on stderr.

## Scope

This is a **teaching tool** for unsalted hashes. The moment a hash is salted (`$apr1$…`, bcrypt `$2y$…`, a separate salt column), or you need real speed, use the proper tools:

```bash
hashcat -m 0 -a 0 hashes.txt rockyou.txt      # raw MD5
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt
```

They run on the GPU, know thousands of hash modes, and handle salts — which is exactly what this script deliberately does not.

## TODO

- Salted modes (`hash(salt + pw)`, `hash(pw + salt)`) when the salt is known.
- `--rules` style mutations (capitalize, leet, append digits) before falling back to the full wordlist.
