#!/usr/bin/env python3
import serial, time, sys, binascii


CANDIDATE_FILE = sys.argv[1]
DEV = sys.argv[2] if len(sys.argv) > 2 else '/dev/cu.usbserial-1130'
BAUD = int(sys.argv[3]) if len(sys.argv) > 3 else 9600
TIMEOUT = 0.6

# Read all candidates
with open(CANDIDATE_FILE, 'r', encoding='utf-8') as f:
    candidates = [l.strip() for l in f if l.strip()]

print(f"Loaded {len(candidates)} candidates.")

def read_all(s, timeout):
    t0 = time.time()
    out = b''
    while time.time() - t0 < timeout:
        d = s.read(4096)
        if not d:
            time.sleep(0.01)
            continue
        out += d
    return out

ser = serial.Serial(DEV, BAUD, timeout=0.1)
time.sleep(0.3)
ser.read(4096)

for cand in candidates:
    variants = [cand, cand + "\n", cand + "\r", cand + "\r\n"]
    for v in variants:
        b = v.encode('utf-8', errors='ignore')
        ser.write(b)
        ser.flush()
        time.sleep(0.15)
        resp = read_all(ser, TIMEOUT)
        text = resp.decode('utf-8', errors='ignore')
        if "ACCESS GRANTED" in text:
            print(f"\nACCESS GRANTED for: {repr(v)}")
            print("Response:")
            print(text)
            ser.close()
            sys.exit(0)
        if "ACCESS DENIED" in text:
            print(f"Denied: {repr(v)}")
        time.sleep(0.05)

ser.close()
print(" No password found. Try adjusting variants or timing.")