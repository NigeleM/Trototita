#!/usr/bin/env bash
# Creates a self-signed certificate for the team server.
# Usage: server/make-cert.sh <server-hostname-or-ip> [days]
# Copy server/cert.pem to every desktop client and set it as "Server certificate file" in Settings.
# For a certificate from your organisation's CA, skip this script and point --cert/--key at those files.
set -euo pipefail

HOST="${1:?Give the server hostname or IP, e.g. vulnmgt-server.local or 10.0.0.5}"
DAYS="${2:-825}"
DIR="$(cd "$(dirname "$0")" && pwd)"

# Only plain host names and IPv4 addresses are accepted, so the value cannot add extra certificate fields.
if [[ "$HOST" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  SAN="IP:${HOST}"
elif [[ "$HOST" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]; then
  SAN="DNS:${HOST}"
else
  echo "Not a valid host name or IPv4 address: ${HOST}" >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
  -days "$DAYS" -subj "/CN=${HOST}" \
  -addext "subjectAltName=${SAN}"

chmod 600 "$DIR/key.pem"
echo "Wrote $DIR/cert.pem (give this file to clients) and $DIR/key.pem (keep on the server only)."
