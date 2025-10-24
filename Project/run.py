#!/usr/bin/env python3
# extract_strings.py

import subprocess
import re
from datetime import datetime
import time
import hashlib
import hmac
from typing import Tuple
from pathlib import Path
import sys

try:
    from Crypto.Hash import keccak, HMAC, SHA3_256
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False



def extract_strings(firmware="firmware.elf", minlen=4, output_file="strings_all.txt"):
    
    """Extracts strings from the ELF file"""

    print("Extraction des chaînes")
    with open(output_file, "w") as f:
        subprocess.run(["strings", "-n", str(minlen), firmware], stdout=f)
    print(f"Chaînes extraites -> {output_file}")
    return output_file


def prioritize_strings(IN="strings_all.txt", OUT="candidates_prioritized.txt"):
    
    """Assigns a relevance score to the strings"""
    
    print("Priorisation des chaînes")
    keywords = [
        "enter password","password","pass","mot de passe","motdepasse",
        "secret","salt","here is your hash","here is your salt",
        "access granted","access denied","vault","hash", "Je suis une petite tortue"
    ]
    

    def score(s):
        ss = s.strip()
        if not ss: return None
        ls = ss.lower()
        sc = 0
        # strong signals
        if any(k in ls for k in keywords): sc += 12
        if ' ' in ss: sc += 10         # phrase boost
        if re.search(r'[A-Za-zÀ-ÖØ-öø-ÿ]', ss): sc += 8
        
        if re.search(r'[éàèùâêîôûçëïü]', ss): sc += 4
        # length
        L = len(ss)
        if 6 <= L <= 40: sc += 3
        elif L < 4: sc -= 4
        # penalties
        if ss.isupper() and ' ' not in ss: sc -= 6
        if re.search(r'(^/|/home/|\.o$|\.S$|gcc|GNU AS|/usr/)', ss): sc -= 8
        if re.match(r'^[0-9A-Fa-f]{32,}$', ss): sc -= 10   # pure long hex = likely hash
        if re.search(r'[^A-Za-z0-9 À-ÖØ-öø-ÿ@#\-_\.:\'"]', ss): sc -= 3
        return (sc, ss)

    items = []
    with open(IN, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            r = score(line.rstrip("\n"))
            if r is None:
                continue
            items.append(r)

    # tri par score décroissant
    items.sort(key=lambda x: (-x[0],))
    with open(OUT, 'w', encoding='utf-8') as o:
        for sc, s in items:
            o.write(f"{sc:03d}\t{s}\n")

    print(f"{len(items)} sorted strings -> {OUT}")
    return OUT

def clean_candidates(IN="candidates_prioritized.txt", OUT="cleaned_candidates.txt"):
    
    """Cleans the file to keep only the strings (without the score)"""
    
    print("cleaning candidates")
    with open(OUT, "w") as f:
        subprocess.run(["cut", "-f2-", IN], stdout=f)
    print(f"cleaned strings -> {OUT}")
    return OUT

from pathlib import Path
import subprocess

from pathlib import Path
import subprocess, sys, os

def try_serial_candidates(candidate_file: str,
                          dev: str = "/dev/cu.usbserial-1130",
                          baud: int = 9600,
                          timeout: float = 0.6,
                          script_path: str = "test_candidates.py",
                          log_file: str = "serial_log.txt"):
    """
    Executes the external script while displaying the output in REAL TIME
    and simultaneously saving it to a file (tee).
    """
    cand = Path(candidate_file)
    if not cand.exists():
        raise FileNotFoundError(f"{candidate_file} not found")

    cmd = ["python3", "-u", script_path, str(cand), dev, str(baud)]
    print("attempt via serial (streaming)")

    # line-buffered streaming
    with open(log_file, "a", encoding="utf-8") as logf:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,           # décode en str
            bufsize=1,           # line-buffered
            env={**os.environ, "PYTHONUNBUFFERED": "1"}  # renfort anti-buffering
        )

        # Affiche et enregistre au fil de l’eau
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            logf.write(line)

        rc = proc.wait()

    if rc != 0:
        raise subprocess.CalledProcessError(rc, cmd)

    print(f"End of serial step → log written to {log_file}")

def parse_serial_log(log_file: str = "serial_log.txt", summary_file: str = "serial_summary.txt"):
    """
    Parses the log file and extracts the lines:
    - ACCESS GRANTED for:
    - Here is your salt:
    - Here is your hash:
    The results are saved in summary_file.
    """
    log_path = Path(log_file)
    if not log_path.exists():
        print(f"File {log_file} not found.")
        return

    interesting_patterns = [
        r"^ACCESS GRANTED for:",
        r"^Here is your salt:",
        r"^Here is your hash:"
    ]

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    results = []
    for line in lines:
        for pattern in interesting_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                results.append(line.strip())
                break  

    if results:
        with open(summary_file, "w", encoding="utf-8") as out:
            for line in results:
                out.write(line + "\n")
        print(f"{len(results)} interesting lines extracted -> {summary_file}")
    else:
        print("No interesting lines found in the log.")



def extract_hash_and_salt(summary_file: str = "serial_filtered.txt") -> Tuple[str, str]:
    """
    Parses summary_file and returns (target_hash, salt).
    - target_hash: lowercase hex string extracted from "Here is your hash: ..."
    - salt: the salt text as it appears (hex string if printed in hex)
    Raises FileNotFoundError if the file is missing, or ValueError if one of the two is not found.
    """
    p = Path(summary_file)
    if not p.exists():
        raise FileNotFoundError(f"{summary_file} not found")

    target_hash = None
    salt = None

    
    re_hash = re.compile(r"Here is your hash:\s*([0-9A-Fa-f]+)", re.IGNORECASE)
    re_salt_hex = re.compile(r"Here is your salt:\s*([0-9A-Fa-f]+)", re.IGNORECASE)
    re_salt_text = re.compile(r"Here is your salt:\s*(.+)", re.IGNORECASE)

    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue

            # Hash first
            m_h = re_hash.search(line)
            if m_h and not target_hash:
                target_hash = m_h.group(1).lower()
                continue

            # Salt as hex
            m_shex = re_salt_hex.search(line)
            if m_shex and not salt:
                salt = m_shex.group(1)   # keep as string (hex)
                continue

            # Salt as generic text (fallback)
            m_stxt = re_salt_text.search(line)
            if m_stxt and not salt:
                salt = m_stxt.group(1).strip()
                continue

    if not target_hash or salt is None:
        raise ValueError("Unable to extract the hash and/or salt from the summary file.")
        
    return target_hash, salt

def call_identify_script(candidates_file: str,
                         target_hash: str,
                         salt: str,
                         script_path: str = "identify_hash.py") -> int:
    """
    Calls the external script (find_hash_and_algo.py) with:
      - candidates_file (e.g., "cleaned_candidates.txt")
      - target_hash (hex string)
      - salt (string; hex or text)
    Automatically detects if the salt is hex and adds the "hex" argument.
    Displays the script output in real time and returns its exit code.
    """
   
    if not Path(candidates_file).exists():
        raise FileNotFoundError(f"{candidates_file} introuvable")
    if not Path(script_path).exists():
        raise FileNotFoundError(f"{script_path} introuvable")

    target_hash = target_hash.strip().lower()
    salt_clean = salt.strip()
    salt_is_hex = bool(re.fullmatch(r"[0-9A-Fa-f]+", salt_clean))

    cmd = ["python3", script_path, candidates_file, target_hash, salt_clean]
    if salt_is_hex:
        cmd.append("hex")

    print(f"-> Executing: {' '.join(cmd)}")
    
    proc = subprocess.run(cmd)
    return proc.returncode



def main():
    firmware = "secure_sketch_v20251015.1.elf"  
    strings_file = extract_strings(firmware) 
    prioritize_strings(strings_file) 
    clean_candidates("candidates_prioritized.txt") 

    try_serial_candidates("cleaned_candidates.txt",
                          dev="/dev/cu.usbserial-1130",
                          baud=9600,
                          timeout=0.6,
                          script_path="test_candidates.py") 
    parse_serial_log("serial_log.txt", "serial_summary.txt")

    try:
        target_hash, salt = extract_hash_and_salt("serial_summary.txt")
        print(f"Hash extrait: {target_hash}")
        print(f"Salt extrait: {salt}")
    except (FileNotFoundError, ValueError) as e:
        print(f"Error while extracting hash and salt: {e}")

    rc = call_identify_script("cleaned_candidates.txt", target_hash, salt,
                              script_path="identify_hash.py")
    if rc == 0:
        print("MATCH found (see found.txt).")
    else:
        print("No match or error (code:", rc, ")")

    


if __name__ == "__main__":
    main()
