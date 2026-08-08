# Paper

Build the current manuscript with:

```bash
./paper/build.sh
```

The deterministic default build writes HTML and LaTeX to `paper/build/`. Set
`TLSN_BUILD_PDF=1` to additionally invoke Tectonic. PDF generation is optional
because the local Tectonic installation currently hangs while resolving its
bundle; that toolchain must be fixed or containerized before submission.

The paper is a living research artifact: its claim-evidence table must remain
synchronized with `STATUS.md` and `formal/verify.sh`.
