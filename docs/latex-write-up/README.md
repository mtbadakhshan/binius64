# LaTeX write-ups

Math + protocol specifications for components of the Binius64 codebase that
benefit from a more formal write-up than inline doc comments.

## Documents

| Source | Subject |
|---|---|
| `akita-bridge.tex` | Verifier-side bridge from Binius's IOP layer (over $\mathbb{F}_{2^{128}}$) to the Akita lattice PCS (over a prime field $\mathbb{F}_p$). Mirrors the implementation in `crates/akita-bridge/`. |

## Build

`latexmk` reads `.latexmkrc` and puts compiled artifacts under `build/`.

```
# one-off build
make

# rebuild on save
make watch

# open the PDF (macOS)
make view

# clean
make clean
```

Requires a working TeX Live (or MacTeX) install. `pdflatex`, `latexmk`,
and the LaTeX packages `amsmath`, `amssymb`, `amsthm`, `algorithm2e`,
`hyperref`, `xcolor`, `geometry`, and `microtype` are sufficient for the
current documents.

## What lives here vs `docs/*.md`

- **`docs/*.md`**: bug reports, audit logs, architectural notes,
  walkthroughs — anything that benefits from being easily readable in a
  GitHub view.
- **`docs/latex-write-up/*.tex`**: formal math / protocol specifications
  with proofs, soundness analyses, and protocol scripts that benefit from
  LaTeX's typesetting (theorems, aligned equations, algorithm
  environments, cross-references, etc.).
