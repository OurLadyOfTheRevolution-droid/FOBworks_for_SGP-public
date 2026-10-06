#!/bin/sh
# Stage the public tree from a git ref, excluding what must not be published, then
# run the disclosure transform over it.
#
# The working tree can't be rsynced out: it holds untracked third-party material
# ("reference sources/", cloned Flipper repos and a stray download archive) that is
# not this project's to publish, and an rsync copies it wholesale. A git archive
# of a ref takes only what is tracked. The two files dropped below are the
# plaintext manufacturer-key corpus and its regression result: the key table is
# exactly what the transform masks elsewhere, so shipping it would undo the masking.
#
# Usage:  tools/publish_stage.sh <ref> <outdir>     (default: main /tmp/pubtree)
set -eu

REF=${1:-main}
OUT=${2:-/tmp/pubtree}
HERE=$(cd "$(dirname "$0")/.." && pwd)

mkdir -p "$OUT"
git -C "$HERE" archive "$REF" | tar -x -C "$OUT"

# The private worklogs and the plaintext key corpus are not part of the public tree.
find "$OUT/research" -maxdepth 1 -name '*.md' -delete 2>/dev/null || true
rm -f "$OUT/research/sources/keeloq_mfcodes_public.txt"
rm -f "$OUT/research/sources/corpus_regression_result.json"

# tools/mask_mfrkeys.py and the published .gitignore live only on the publish and
# public branches, so they are not in a main archive. Carry them over when that
# ref is available; the published .gitignore also documents what is not shipped.
if git -C "$HERE" rev-parse --verify --quiet publish >/dev/null; then
    git -C "$HERE" show publish:tools/mask_mfrkeys.py > "$OUT/tools/mask_mfrkeys.py"
    git -C "$HERE" show publish:.gitignore > "$OUT/.gitignore"
fi

python3 "$HERE/tools/publish_prepare.py" --out "$OUT"
