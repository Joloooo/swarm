#!/usr/bin/env bash
# Download real wordlists into SwarmAttacker/wordlists/ as FLAT basenames, so
# the gobuster resolver's bundled-dir fallback (src/tools/web_recon/gobuster.py,
# step 4 — matches Path(rel).name) finds them with no code change:
#   common  -> common.txt
#   medium  -> raft-medium-directories.txt / directory-list-2.3-medium.txt
#   big     -> raft-large-directories.txt / big.txt
# Plus usernames/passwords + rockyou for credential work. The large lists are
# gitignored; only common.txt + README stay tracked as the guaranteed fallback.
#
# Idempotent — re-running skips files already present (common.txt is always
# refreshed since it is the committed fallback and must be the real list).
#
# Run:  ./scripts/download_wordlists.sh
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/wordlists"
SL="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
mkdir -p "$DIR"

fetch() {  # url dest [force]
  local url="$1" dest="$2" force="${3:-}"
  if [[ -z "$force" && -s "$dest" ]]; then echo "skip  $(basename "$dest") (exists)"; return; fi
  if curl -fsSL "$url" -o "$dest.part" && [[ -s "$dest.part" ]]; then
    mv "$dest.part" "$dest"
    echo "ok    $(basename "$dest")  ($(wc -l < "$dest" | tr -d ' ') lines, $(du -h "$dest" | cut -f1))"
  else
    echo "FAIL  $(basename "$dest")  <- $url"; rm -f "$dest.part"
  fi
}

echo "== directory / content discovery (gobuster common/medium/big presets) =="
fetch "$SL/Discovery/Web-Content/common.txt"                    "$DIR/common.txt" force
fetch "$SL/Discovery/Web-Content/raft-medium-directories.txt"   "$DIR/raft-medium-directories.txt"
fetch "$SL/Discovery/Web-Content/raft-medium-files.txt"         "$DIR/raft-medium-files.txt"
fetch "$SL/Discovery/Web-Content/raft-large-directories.txt"    "$DIR/raft-large-directories.txt"
fetch "$SL/Discovery/Web-Content/directory-list-2.3-medium.txt" "$DIR/directory-list-2.3-medium.txt"
fetch "$SL/Discovery/Web-Content/big.txt"                       "$DIR/big.txt"

echo "== usernames / passwords =="
fetch "$SL/Usernames/top-usernames-shortlist.txt"              "$DIR/top-usernames-shortlist.txt"
fetch "$SL/Passwords/Common-Credentials/10-million-password-list-top-100000.txt" "$DIR/passwords-top-100000.txt"

echo "== rockyou (SecLists ships it tar.gz, ~50MB -> ~140MB) =="
if [[ -s "$DIR/rockyou.txt" ]]; then
  echo "skip  rockyou.txt (exists)"
elif curl -fsSL "$SL/Passwords/Leaked-Databases/rockyou.txt.tar.gz" -o "$DIR/rockyou.txt.tar.gz"; then
  tar xzf "$DIR/rockyou.txt.tar.gz" -C "$DIR" && rm -f "$DIR/rockyou.txt.tar.gz" \
    && echo "ok    rockyou.txt  ($(wc -l < "$DIR/rockyou.txt" | tr -d ' ') lines, $(du -h "$DIR/rockyou.txt" | cut -f1))"
else
  echo "FAIL  rockyou.txt.tar.gz"
fi

echo
echo "done -> $DIR"
ls -lh "$DIR"
