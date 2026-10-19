#!/usr/bin/env bash
# Creates a self-signed certificate for the team server.
# Usage: server/make-cert.sh <server-hostname-or-ip> [days]
# Copy server/cert.pem to every desktop client and set it as "Server certificate file" in Settings.
# For a certificate from your organisation's CA, skip this script and point --cert/--key at those files.
set -euo pipefail

HOST="${1:?Give the server hostname or IP, e.g. vulnmgt-server.local or 10.0.0.5}"
DAYS="${2:-825}"
DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ "$HOST" =~ ^[0-9.]+$ ]]; then SAN="IP:${HOST}"; else SAN="DNS:${HOST}"; fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
  -days "$DAYS" -subj "/CN=${HOST}" \
  -addext "subjectAltName=${SAN}"

chmod 600 "$DIR/key.pem"
echo "Wrote $DIR/cert.pem (give this file to clients) and $DIR/key.pem (keep on the server only)."
