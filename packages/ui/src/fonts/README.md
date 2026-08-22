# Webfonts

`@font-face` declarations for these files live in [`../styles/globals.css`](../styles/globals.css),
Section 2. The `url()` paths there are relative to that file, so the filenames
below are load-bearing — renaming one silently breaks the family it backs.

The `.woff2` binaries are **not committed**. Domaine Display and ABC Favorit are
commercial families and this repository is public, so the files are gitignored
rather than redistributed. A fresh clone builds and runs; the affected families
fall through to the next entry in their `--font-*` stack until the files are
placed here.

## Expected files

| File | Family | Weight | Style | Source |
|---|---|---|---|---|
| `domaine-display-400.woff2` | `Domaine Display` | 400 | normal | Klim Type Foundry |
| `abc-favorit-700.woff2` | `ABC Favorit` | 700 | normal | Dinamo |
| `abc-favorit-mono-350.woff2` | `ABC Favorit Mono` | 400 | normal | Dinamo |
| `abc-favorit-mono-350-italic.woff2` | `ABC Favorit Mono` | 400 | italic | Dinamo |
| `abc-favorit-mono-700.woff2` | `ABC Favorit Mono` | 700 | normal | Dinamo |
| `abc-favorit-mono-700-italic.woff2` | `ABC Favorit Mono` | 700 | italic | Dinamo |

`abc-favorit-mono-350*` keeps the foundry's own weight number in its filename —
the face reports `usWeightClass: 350` ("Book") but is declared at 400, because it
is the family's regular cut and `font-normal` should reach it directly rather
than via nearest-weight fallback.

## Converting a new face

Source files arrive as `.otf`. Convert the container without touching the
outlines or the name table:

```bash
python3 -m venv /tmp/fontvenv && /tmp/fontvenv/bin/pip install 'fonttools[woff]'
/tmp/fontvenv/bin/python -c "
from fontTools.ttLib import TTFont
f = TTFont('Input.otf'); f.flavor = 'woff2'; f.save('output.woff2')"
```

The family name in `globals.css` is whatever the `@font-face` block declares, not
what the file's internal name table says, so a trial or renamed source file needs
no patching.

## Known limitation: the Domaine Display cut

The Domaine Display file currently in use is the trial cut. It carries 66
codepoints — letters, digits, space, comma, hyphen, period — and no `GSUB`
table, so the `ss01 / ss04 / ss11` sets DESIGN.md specifies are inert.

The `unicode-range` on its `@font-face` declares that limit, so anything outside
it resolves against the next family in the stack. A display headline containing
an apostrophe or a question mark will visibly mix two serifs. Replacing the file
with a retail cut needs no code change beyond dropping the `unicode-range`.
