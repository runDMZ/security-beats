# 🎧 Web auth

Offline attacks against HTTP authentication schemes, to show *why* a given scheme fails and what fixes it.

| Script | What it does | Input |
|---|---|---|
| [`digest_crack.py`](digest_crack.py) | Recovers the password behind an **HTTP Digest** authentication from a single captured `Authorization: Digest` header, by replaying the `response` computation against a wordlist | the captured header + a wordlist |

## Why Digest can still fall

HTTP **Basic** sends `base64(user:password)` — anyone who sniffs the request reads the password directly (base64 is encoding, not encryption). **Digest** (RFC 2617) was meant to fix that: the password never travels. Instead the client sends a hash:

```
HA1      = MD5(username : realm : password)
HA2      = MD5(method : uri)
response = MD5(HA1 : nonce : nc : cnonce : qop : HA2)      # qop=auth
response = MD5(HA1 : nonce : HA2)                          # legacy, no qop (RFC 2069)
```

A sniffer never sees the password — but everything else in that formula is on the wire. So if the password is weak, it falls to an **offline** attack: for each candidate, recompute `response` and compare to the captured one. No traffic to the server, no lockout, no rate limit — it is pure local hashing, as fast as the wordlist and the CPU allow.

The lesson: Digest protects the password in transit, nothing more (the session cookie, for one, is still sniffable), and it does not protect a weak password at all. **The real fix is TLS** — encrypt the transport and the sniff itself becomes impossible, whatever auth scheme sits behind it.

## Usage

```bash
# Header pasted inline (copy it straight from Wireshark: filter http.authorization)
./digest_crack.py \
  -H 'Authorization: Digest username="alice", realm="area", nonce="...", uri="/path", response="...", qop=auth, nc=00000001, cnonce="..."' \
  -w /path/to/rockyou.txt -m GET

# Or read the header from a file
./digest_crack.py -H @header.txt -w rockyou.txt
```

Output on success:

```
[+] TROUVÉ -> alice:<password>  (ligne 9143)
```

## Notes

- Parses the header itself — no parameter is hard-coded, so it works on any captured Digest exchange.
- Handles `qop=auth` and the legacy no-`qop` form (RFC 2069), and `algorithm=MD5` / `MD5-sess`.
- Default HTTP method is `GET`; set `-m` for the method actually used in the capture (it feeds `HA2`).
- **No real data**: pass the capture from the command line, nothing is stored in the script.

## TODO

- `algorithm=SHA-256` / `SHA-512-256` (RFC 7616): same logic, swap the hash function on the `algorithm` field.
- `qop=auth-int`: needs the request body hash in `HA2`.
