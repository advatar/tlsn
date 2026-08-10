#!/usr/bin/env bash
set -euo pipefail

mkdir -p paper/build output/pdf
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

tectonic \
  --outdir output/pdf \
  paper/build/tls13-tlsnotary.tex
