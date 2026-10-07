#!/bin/sh
# Stage the public tree from a git ref, excluding what must not be published, then
# run the disclosure transform over it.
#
# The working tree can't be rsynced out: it holds untracked third-party material
# ("reference sources/", cloned Flipper repos and a stray download archive) that is
# not this project's to publish, and an rsync copies it wholesale. A git archive
# of a ref takes only what is tracked. The files dropped below are the plaintext
# manufacturer-key corpus and its raw regression JSON: the key table is exactly
# what the transform masks elsewhere, and the human ledger is docs/CORPUS_SCORECARD.md.
#
# Measured-limits research notes listed in tools/publish_whitelist.txt are kept.
#
# Usage:  tools/publish_stage.sh <ref> <outdir>     (default: main /tmp/pubtree)
set -eu

REF=${1:-main}
OUT=${2:-/tmp/pubtree}
HERE=$(cd "$(dirname "$0")/.." && pwd)
WHITELIST="$HERE/tools/publish_whitelist.txt"
PUB_GI="$HERE/tools/publish.gitignore"

mkdir -p "$OUT"
git -C "$HERE" archive "$REF" | tar -x -C "$OUT"

# Drop private worklogs, then restore the measured-limits whitelist. Prefer the
# working-tree copy of each note (so a redact that is about to be committed is
# what ships); fall back to the archived blob when the working tree lacks it.
KEEP=$(mktemp -d)
if [ -f "$WHITELIST" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    if [ -f "$HERE/research/$line" ]; then
      cp "$HERE/research/$line" "$KEEP/$line"
    elif [ -f "$OUT/research/$line" ]; then
      cp "$OUT/research/$line" "$KEEP/$line"
    fi
  done < "$WHITELIST"
fi
find "$OUT/research" -maxdepth 1 -name '*.md' -delete 2>/dev/null || true
if [ -d "$KEEP" ]; then
  for f in "$KEEP"/*; do
    [ -f "$f" ] || continue
    cp "$f" "$OUT/research/$(basename "$f")"
  done
  rm -rf "$KEEP"
fi
# Overlay the working-tree copies of the honesty surfaces so an uncommitted
# redact/count/version bump is what the transform and publish_check see.
if [ -d "$HERE/docs" ]; then
  mkdir -p "$OUT/docs"
  cp -R "$HERE/docs/." "$OUT/docs/"
fi
for f in PROMO.md README.md CITATIONS_AND_REFERENCES.md; do
  if [ -f "$HERE/$f" ]; then
    cp "$HERE/$f" "$OUT/$f"
  fi
done
for f in tools/publish_prepare.py tools/publish_check.py tools/publish_whitelist.txt tools/publish.gitignore tools/gen_corpus_scorecard.py tools/mask_mfrkeys.py; do
  if [ -f "$HERE/$f" ]; then
    mkdir -p "$OUT/$(dirname "$f")"
    cp "$HERE/$f" "$OUT/$f"
  fi
done

rm -f "$OUT/research/sources/keeloq_mfcodes_public.txt"
rm -f "$OUT/research/sources/corpus_regression_result.json"

# Published .gitignore and the mask helper. Prefer the tracked copies on this
# branch; fall back to the publish branch when an older ref is staged.
if [ -f "$PUB_GI" ]; then
  cp "$PUB_GI" "$OUT/.gitignore"
elif git -C "$HERE" rev-parse --verify --quiet publish >/dev/null; then
  git -C "$HERE" show publish:.gitignore > "$OUT/.gitignore"
fi
if [ -f "$HERE/tools/mask_mfrkeys.py" ]; then
  : # already in the archive when tracked on main
elif git -C "$HERE" rev-parse --verify --quiet publish >/dev/null; then
  git -C "$HERE" show publish:tools/mask_mfrkeys.py > "$OUT/tools/mask_mfrkeys.py"
fi
# mask_mfrkeys lives only on publish today; carry it when missing from the archive.
if [ ! -f "$OUT/tools/mask_mfrkeys.py" ] && git -C "$HERE" rev-parse --verify --quiet publish >/dev/null; then
  git -C "$HERE" show publish:tools/mask_mfrkeys.py > "$OUT/tools/mask_mfrkeys.py"
fi

python3 "$HERE/tools/publish_prepare.py" --out "$OUT"
