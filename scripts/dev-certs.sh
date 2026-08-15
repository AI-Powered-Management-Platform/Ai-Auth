#!/usr/bin/env bash
# Mint the DEVELOPMENT PKI: one throwaway CA, a server cert for the Guard,
# a client cert for the gateway. Output is gitignored; certificates are
# mounted at runtime and never enter an image (deploy/README).
# Production uses the internal CA with 24h rotation — this script is the
# dev stand-in, not the design.
set -euo pipefail

# Git Bash on Windows: stop MSYS rewriting /CN=... into C:/Program Files/...,
# and hand native openssl a Windows-style base path (pwd -W). Both are
# no-ops on Linux and macOS.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
ROOT="$(cd "$(dirname "$0")/.." && (pwd -W 2>/dev/null || pwd))"
OUT="$ROOT/deploy/dev-certs"
DAYS=3
mkdir -p "$OUT"

echo "minting dev PKI into $OUT (valid $DAYS days)"

openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca-key.pem"
openssl req -new -x509 -key "$OUT/ca-key.pem" -out "$OUT/ca.pem" -days "$DAYS" \
  -subj "/CN=aiauth-dev-ca" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign"

leaf() { # name eku san
  local name="$1" eku="$2" san="$3"
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/$name-key.pem"
  openssl req -new -key "$OUT/$name-key.pem" -out "$OUT/$name.csr" -subj "/CN=$name"
  # a real ext file, not process substitution — native Windows openssl
  # cannot read /proc/fd paths
  printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n" \
    "$eku" "$san" > "$OUT/$name.ext"
  openssl x509 -req -in "$OUT/$name.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca-key.pem" \
    -CAcreateserial -out "$OUT/$name.pem" -days "$DAYS" -extfile "$OUT/$name.ext"
  rm -f "$OUT/$name.csr" "$OUT/$name.ext"
}

leaf crypto  serverAuth "DNS:crypto"
leaf gateway clientAuth "DNS:gateway"

rm -f "$OUT/ca.srl"
chmod 600 "$OUT"/*-key.pem
echo "done:"
ls "$OUT"
