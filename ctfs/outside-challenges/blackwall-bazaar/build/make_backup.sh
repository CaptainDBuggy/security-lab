#!/usr/bin/env sh
# ---------------------------------------------------------------------------
# Builds the encrypted site backup that gets "accidentally" left in the vault.
#
# ZipCrypto (traditional PKWARE) encryption ON PURPOSE — it's vulnerable to a
# known-plaintext attack (bkcrack) using the public index.html as the crib. The
# zip password itself is a throwaway random string; nobody's meant to crack the
# password, they crack the keystream from the known plaintext.
#
# Explicit file list (NOT a recursive copy) so we never accidentally sweep a
# later-stage source file into the backup and spoil it.
# ---------------------------------------------------------------------------
set -e
cd "$(dirname "$0")/.."

mkdir -p vault
# (the per-ware .bin files are generated at boot by build/populate_vault.js)

STAGE=".backup_staging"
rm -rf "$STAGE"
mkdir -p "$STAGE/src/routes"

# index.html = the known-plaintext crib (must byte-match what the app serves)
cp public/index.html "$STAGE/index.html"
# the payload the backup actually leaks: the salt + hashing scheme
cp src/crypto.js "$STAGE/src/crypto.js"
cp src/db.js "$STAGE/src/db.js"
cp src/invite.js "$STAGE/src/invite.js"
cp src/routes/auth.js "$STAGE/src/routes/auth.js"
cp package.json "$STAGE/package.json"

ZIPPW="$(head -c 18 /dev/urandom | base64 | tr -d '/+=\n')"

rm -f vault/nc_market_backup_0417.zip
# Store index.html UNCOMPRESSED (-0) so it's a clean known-plaintext crib for
# bkcrack (raw file bytes == stored bytes). The rest can be deflated (-9).
( cd "$STAGE" \
  && zip -q -0 --encrypt -P "$ZIPPW" ../vault/nc_market_backup_0417.zip index.html \
  && zip -q -9 -r --encrypt -P "$ZIPPW" ../vault/nc_market_backup_0417.zip src package.json )
rm -rf "$STAGE"

echo "[backup] built vault/nc_market_backup_0417.zip (ZipCrypto, pw hidden)"
