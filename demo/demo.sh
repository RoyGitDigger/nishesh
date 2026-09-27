#!/usr/bin/env bash
# NISHESH — screen-recording demonstration.
#
#   ./demo/demo.sh          paced for recording (pauses between acts)
#   ./demo/demo.sh --fast   no pauses, for CI and quick checks
#
# Record with:  asciinema rec nishesh.cast   (or OBS / any screen recorder)
# Terminal:     at least 100 columns, a dark theme, 14-16pt font.

set -euo pipefail
cd "$(dirname "$0")/.."

BIN=./target/release/nishesh
FAST=${1:-}
IMG=demo/evidence.img
MANIFEST=demo/evidence.manifest.json
TARGET=demo/wipe-target.img
CERT=demo/certificate.json
CHAIN=demo/chain.jsonl

clr()   { [ "$FAST" = "--fast" ] || clear; }
pause() { [ "$FAST" = "--fast" ] || { echo; read -rp $'\033[2m  [enter]\033[0m'; clear; }; }
act()   { clr; echo; printf '\033[38;5;37m  ══ %s ══\033[0m\n' "$1"; echo; sleep 0.4; }

[ -x "$BIN" ] || { echo "build first:  cargo build --release"; exit 1; }
rm -f "$CHAIN" "$CERT" "$TARGET"

# ---------------------------------------------------------------- ACT ZERO
clr
$BIN --help | head -12
pause

# ----------------------------------------------------------------- ACT ONE
act "ACT 1 — build evidence with known ground truth"
$BIN testgen --out "$IMG" --size-mb 20 --no-banner
pause

# ----------------------------------------------------------------- ACT TWO
act "ACT 2 — M1 device access: the drive is lying about its size"
$BIN identify "$IMG" --as sata-ssd --hpa 2048 --dco 1024 --no-banner
pause

# --------------------------------------------------------------- ACT THREE
act "ACT 3 — M2 recovery: get the deleted files back, graded by hash"
$BIN recover "$IMG" --manifest "$MANIFEST" --out demo/recovered --no-banner
echo
echo "  The recovered files are real. Open one:"
ls -la demo/recovered/ | head -8
pause

# ---------------------------------------------------------------- ACT FOUR
act "ACT 4 — M3 policy: the tool REFUSES when it cannot honestly certify"
$BIN sanitize "$IMG" --as usb --no-banner || true
echo
printf '\033[2m  A USB bridge blocks command passthrough. A lesser tool would quietly\033[0m\n'
printf '\033[2m  fall back to a software overwrite and print a certificate anyway.\033[0m\n'
pause

# ---------------------------------------------------------------- ACT FIVE
act "ACT 5 — the loop: wipe it, then ATTACK the wipe"
cp "$IMG" "$TARGET"
$BIN sanitize "$TARGET" --as sata-ssd --hpa 2048 --dco 1024 \
     --execute --confirm --samples 3000 \
     --cert "$CERT" --log "$CHAIN" --no-banner
pause

# ----------------------------------------------------------------- ACT SIX
act "ACT 6 — M4 proof: verify the certificate offline"
$BIN verify-cert "$CERT" --log "$CHAIN" --no-banner
pause

# --------------------------------------------------------------- ACT SEVEN
act "ACT 7 — now forge it"
printf '\033[2m  Editing one field in the signed payload, the way an operator\033[0m\n'
printf '\033[2m  hiding a failed wipe would.\033[0m\n\n'
python3 - <<'PY'
import json
c = json.load(open('demo/certificate.json'))
c['payload']['device']['serial'] = 'FORGED-SERIAL'
json.dump(c, open('demo/tampered.json', 'w'), indent=2)
print('  demo/tampered.json written — one field changed, nothing else')
PY
echo
$BIN verify-cert demo/tampered.json --log "$CHAIN" --no-banner || true
pause

# --------------------------------------------------------------- ACT EIGHT
act "ACT 8 — the test suite"
cargo test --quiet 2>&1 | tail -6
echo
printf '\033[2m  SHA-256 against the FIPS 180-4 vectors. HMAC against RFC 4231.\033[0m\n'
printf '\033[2m  Merkle proofs verified for every leaf. Policy engine asserted to\033[0m\n'
printf '\033[2m  REFUSE on flash without a firmware erase — the failure mode this\033[0m\n'
printf '\033[2m  whole project exists to prevent.\033[0m\n'
echo
