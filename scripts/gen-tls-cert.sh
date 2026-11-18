#!/bin/sh
# Generate a locally trusted TLS certificate for the Caddy HTTPS proxy.
# Each developer runs this on their own machine: it installs mkcert's local CA
# into this machine's trust store and issues a certificate signed by it.
#
# Usage: scripts/gen-tls-cert.sh [--force] [extra-hostname-or-ip ...]
set -eu

cd "$(dirname "$0")/.."
TLS_DIR=secrets/tls
CERT="$TLS_DIR/cert.pem"
KEY="$TLS_DIR/key.pem"

FORCE=0
if [ "${1:-}" = "--force" ]; then
    FORCE=1
    shift
fi

if ! command -v mkcert >/dev/null 2>&1; then
    echo "mkcert is not installed. Please install it." >&2
    echo "  macOS:  brew install mkcert nss" >&2
    echo "  Linux:  install mkcert and libnss3-tools from your package manager," >&2
    echo "          or download mkcert from https://github.com/FiloSottile/mkcert/releases" >&2
    exit 1
fi

if [ "$FORCE" -eq 0 ] && { [ -e "$CERT" ] || [ -e "$KEY" ]; }; then
    echo "TLS certificate already exists in $TLS_DIR. Re-run with --force to replace it." >&2
    exit 1
fi

mkcert -install

mkdir -p "$TLS_DIR"
mkcert -cert-file "$CERT" -key-file "$KEY" localhost 127.0.0.1 ::1 "$@"
chmod 600 "$KEY"

echo "Certificate written to $CERT. Start the stack and open https://localhost"
