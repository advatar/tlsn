#!/usr/bin/env bash
set -euo pipefail

mkdir -p paper/build
pandoc paper/paper.md \
  --from markdown \
  --citeproc \
  --bibliography paper/references.bib \
  --standalone \
  --to html5 \
  --output paper/build/tls13-tlsnotary.html

pandoc paper/paper.md \
  --from markdown \
  --citeproc \
  --bibliography paper/references.bib \
  --standalone \
  --to latex \
  --output paper/build/tls13-tlsnotary.tex

if [[ "${TLSN_BUILD_PDF:-0}" == "1" ]]; then
  tectonic \
    --outdir paper/build \
    paper/build/tls13-tlsnotary.tex
fi
