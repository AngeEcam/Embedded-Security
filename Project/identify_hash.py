#!/usr/bin/env python3
"""
Usage:
  ./find_hash_and_algo.py <candidates.txt> <target_hash_hex> <salt> [hex]

If salt is printed as hex (e.g. 55326074) pass "hex" as 4th arg.
The script will try for each candidate:
  - SHA256, SHA3-256, Keccak-256 (if pycryptodome available)
  - HMAC-SHA256, HMAC-SHA3 (if pycryptodome available)
  and modes: pwd, salt+pwd, pwd+salt
Stops on first match and writes found.txt with details.
"""
import sys, hashlib, hmac, time, re
try:
    from Crypto.Hash import keccak, HMAC, SHA3_256
    have_crypto = True
except Exception:
    have_crypto = False

if len(sys.argv) < 4:
    print("Usage: ./find_hash_and_algo.py candidates.txt target_hash salt [hex]")
    sys.exit(1)

candidates_file = sys.argv[1]
target = sys.argv[2].strip().lower()
salt_in = sys.argv[3]
salt_is_hex = len(sys.argv) > 4 and sys.argv[4].lower() in ("hex","1","true")

salt = bytes.fromhex(salt_in) if salt_is_hex else salt_in.encode()

def sha256_hex(b): return hashlib.sha256(b).hexdigest()
def sha3_hex(b): return hashlib.sha3_256(b).hexdigest()
def hmac_sha256_hex(key,msg): return hmac.new(key, msg, hashlib.sha256).hexdigest()
def keccak_hex(b):
    if not have_crypto: return None
    k = keccak.new(digest_bits=256); k.update(b); return k.hexdigest()
def hmac_sha3_hex(key,msg):
    if not have_crypto: return None
    h = HMAC.new(key=key, digestmod=SHA3_256); h.update(msg); return h.hexdigest()

algos = [
    ("SHA256", sha256_hex),
    ("SHA3-256", sha3_hex),
]
if have_crypto:
    algos += [("Keccak-256", keccak_hex)]
# hmac separate handling

modes = [
    ("pwd", lambda p: p),
    ("salt+pwd", lambda p: salt + p),
    ("pwd+salt", lambda p: p + salt)
]

start = time.time()
with open(candidates_file, 'r', encoding='utf-8', errors='ignore') as f:
    for lineno, line in enumerate(f,1):
        cand = line.rstrip("\n\r")
        if not cand: continue
        b_pwd = cand.encode()
        for alg_name, alg_fun in algos:
            for mode_name, mode_fun in modes:
                buf = mode_fun(b_pwd)
                try:
                    h = alg_fun(buf)
                except Exception:
                    h = None
                if h and h.lower() == target:
                    with open("found.txt","w",encoding="utf-8") as fo:
                        fo.write(f"FOUND: candidate={cand!r}\n")
                        fo.write(f"line={lineno}\n")
                        fo.write(f"algorithm={alg_name}\n")
                        fo.write(f"mode={mode_name}\n")
                        fo.write(f"hash={h}\\n")
                        fo.write(f"salt_is_hex={salt_is_hex}\\n")
                    print("MATCH FOUND -> wrote found.txt")
                    sys.exit(0)
        # Try HMAC variants
        # HMAC-SHA256
        for mode_name, mode_fun in modes:
            buf = mode_fun(b_pwd)
            try:
                h = hmac_sha256_hex(salt, b_pwd)  # HMAC uses key=salt, msg=pwd
            except Exception:
                h = None
            if h and h.lower() == target:
                with open("found.txt","w",encoding="utf-8") as fo:
                    fo.write(f"FOUND: candidate={cand!r}\n")
                    fo.write(f"line={lineno}\n")
                    fo.write(f"algorithm=HMAC-SHA256\n")
                    fo.write(f"mode=hmac(key=salt,msg=pwd)\n")
                    fo.write(f"hash={h}\\n")
                    fo.write(f"salt_is_hex={salt_is_hex}\\n")
                print("MATCH FOUND (HMAC-SHA256) -> wrote found.txt")
                sys.exit(0)
        if have_crypto:
            try:
                h = hmac_sha3_hex(salt, b_pwd)
            except Exception:
                h = None
            if h and h.lower() == target:
                with open("found.txt","w",encoding="utf-8") as fo:
                    fo.write(f"FOUND: candidate={cand!r}\n")
                    fo.write(f"line={lineno}\n")
                    fo.write(f"algorithm=HMAC-SHA3\n")
                    fo.write(f"mode=hmac(key=salt,msg=pwd)\n")
                    fo.write(f"hash={h}\\n")
                    fo.write(f"salt_is_hex={salt_is_hex}\\n")
                print("MATCH FOUND (HMAC-SHA3) -> wrote found.txt")
                sys.exit(0)
end = time.time()
print("Finished. No match found. Time:", round(end-start,2), "s")