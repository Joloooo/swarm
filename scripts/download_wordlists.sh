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

echo "== CMS component slugs (wp-plugins preset — recon/fuzzing plugin enum) =="
# The SecLists CMS plugin list is dated: it omits modern + known-vulnerable
# plugins (no backup-backup → CVE-2023-6553, no elementor, no woocommerce).
# So we rebuild it to BARE slugs and prepend a curated, version-controlled
# block of high-value slugs (probed first, before the long common tail under a
# run timer). The committed wordlists/wp-plugins.txt is the guaranteed
# fallback; this step refreshes/extends it idempotently.
WP_CVE_EXTRA="all-in-one-wp-migration backup-backup better-search-replace bricks duplicator elementor essential-addons-for-elementor-lite forminator litespeed-cache ninja-forms profile-builder really-simple-ssl royal-elementor-addons ultimate-member woocommerce wp-automatic wp-fastest-cache wp-file-manager wp-statistics wpforms-lite"
if curl -fsSL "$SL/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt" -o "$DIR/.wp-plugins.fuzz.part"; then
  # SecLists entries look like `wp-content/plugins/<slug>/` → reduce to <slug>.
  sed -E 's#^wp-content/plugins/##; s#/+$##' "$DIR/.wp-plugins.fuzz.part" \
    | grep -E '^[A-Za-z0-9._%~-]+$' | sort -u > "$DIR/.wp-base.part"
  printf '%s\n' $WP_CVE_EXTRA | sort -u > "$DIR/.wp-extra.part"
  # curated CVE/modern slugs first, then the SecLists base minus those dupes.
  { cat "$DIR/.wp-extra.part"; comm -23 "$DIR/.wp-base.part" "$DIR/.wp-extra.part"; } > "$DIR/wp-plugins.txt"
  rm -f "$DIR/.wp-plugins.fuzz.part" "$DIR/.wp-base.part" "$DIR/.wp-extra.part"
  echo "ok    wp-plugins.txt  ($(wc -l < "$DIR/wp-plugins.txt" | tr -d ' ') slugs, $(du -h "$DIR/wp-plugins.txt" | cut -f1); backup-backup $(grep -qx backup-backup "$DIR/wp-plugins.txt" && echo present || echo MISSING))"
else
  echo "WARN  could not refresh wp-plugins.txt from SecLists — keeping committed copy"
fi

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
