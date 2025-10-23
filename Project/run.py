#!/usr/bin/env python3
# extract_strings.py

import subprocess
import re
from pathlib import Path
from datetime import datetime
import time
import hashlib
import hmac
from typing import Tuple

try:
    from Crypto.Hash import keccak, HMAC, SHA3_256
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False



def extract_strings(firmware="firmware.elf", minlen=4, output_file="strings_all.txt"):
    
    """Extrait les chaînes du fichier ELF"""

    print("Extraction des chaînes")
    with open(output_file, "w") as f:
        subprocess.run(["strings", "-n", str(minlen), firmware], stdout=f)
    print(f"Chaînes extraites -> {output_file}")
    return output_file


def prioritize_strings(IN="strings_all.txt", OUT="candidates_prioritized.txt"):
    
    """Attribue un score aux chaînes selon leur pertinence"""
    
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

    print(f"{len(items)} chaînes triées -> {OUT}")
    return OUT

def clean_candidates(IN="candidates_prioritized.txt", OUT="cleaned_candidates.txt"):
    
    """Nettoie le fichier pour ne garder que les chaînes (sans le score)"""
    
    print("Nettoyage des candidats")
    with open(OUT, "w") as f:
        subprocess.run(["cut", "-f2-", IN], stdout=f)
    print(f"Chaînes nettoyées -> {OUT}")
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
    Exécute le script externe en affichant la sortie EN TEMPS RÉEL
    et en l'enregistrant simultanément dans un fichier (tee).
    """
    cand = Path(candidate_file)
    if not cand.exists():
        raise FileNotFoundError(f"{candidate_file} introuvable")

    cmd = ["python3", "-u", script_path, str(cand), dev, str(baud)]
    print("Tentative via serial (streaming)")

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

    print(f"Fin de l'étape serial —> log écrit dans {log_file}")

def parse_serial_log(log_file: str = "serial_log.txt", summary_file: str = "serial_summary.txt"):
    """
    Parcourt le fichier log et extrait les lignes :
    - ACCESS GRANTED for:
    - Here is your salt:
    - Here is your hash:
    Les résultats sont sauvegardés dans summary_file.
    """
    log_path = Path(log_file)
    if not log_path.exists():
        print(f"Fichier {log_file} introuvable.")
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
                break  # pour éviter les doublons si plusieurs regex matchent

    if results:
        with open(summary_file, "w", encoding="utf-8") as out:
            for line in results:
                out.write(line + "\n")
        print(f"{len(results)} lignes intéressantes extraites -> {summary_file}")
    else:
        print(" Aucune ligne intéressante trouvée dans le log.")

from pathlib import Path
import re
import subprocess
import sys

def extract_hash_and_salt(summary_file: str = "serial_filtered.txt") -> Tuple[str, str]:
    """
    Parcourt summary_file et retourne (target_hash, salt).

    - target_hash : chaîne hex (lowercase) extraite de "Here is your hash: ..."
    - salt        : texte du salt tel qu'il apparaît (hex string si imprimé en hex)

    Lève FileNotFoundError si le fichier est manquant, ValueError si l'un des deux introuvables.
    """
    p = Path(summary_file)
    if not p.exists():
        raise FileNotFoundError(f"{summary_file} introuvable")

    target_hash = None
    salt = None

    # Patterns gérant exemples variés (avec ou sans "Denied: '...'", CR/LF, etc.)
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
        raise ValueError("Impossible d'extraire le hash et/ou le salt depuis le fichier résumé.")

    return target_hash, salt

def call_identify_script(candidates_file: str,
                         target_hash: str,
                         salt: str,
                         script_path: str = "identify_hash.py") -> int:
    """
    Appelle le script externe (find_hash_and_algo.py) en lui passant :
      - candidates_file (ex: "cleaned_candidates.txt")
      - target_hash (hex string)
      - salt (string; hex or text)
    Détecte automatiquement si salt est hex et ajoute l'argument "hex".
    Affiche la sortie du script en temps réel et retourne son code de sortie.
    """
    # vérifications minimales
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
    # subprocess.run sans capture_output affiche la sortie en direct
    proc = subprocess.run(cmd)
    return proc.returncode



def main():
    firmware = "secure_sketch_v20251015.1.elf"  # Nom du fichier firmware ELF
    strings_file = extract_strings(firmware) # Extrait les chaînes du firmware
    prioritize_strings(strings_file) # Priorise les chaînes extraites
    clean_candidates("candidates_prioritized.txt") # Nettoie le fichier des candidats

    try_serial_candidates("cleaned_candidates.txt",
                          dev="/dev/cu.usbserial-1130",
                          baud=9600,
                          timeout=0.6,
                          script_path="test_candidates.py") # Tente les candidats via le port série
    parse_serial_log("serial_log.txt", "serial_summary.txt") # Analyse le log série

    try:
        target_hash, salt = extract_hash_and_salt("serial_summary.txt")
        print(f"Hash extrait: {target_hash}")
        print(f"Salt extrait: {salt}")
    except (FileNotFoundError, ValueError) as e:
        print(f"Erreur lors de l'extraction du hash et du salt: {e}") 

    rc = call_identify_script("cleaned_candidates.txt", target_hash, salt,
                              script_path="identify_hash.py")
    if rc == 0:
        print("MATCH trouvé (voir found.txt).")
    else:
        print("Aucun match ou erreur (code:", rc, ")")

    


if __name__ == "__main__":
    main()
