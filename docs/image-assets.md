# Raster image assets

Everything drawn for this platform is vector — the icon set, the illustration set
and the tab mark are all hand-authored SVG in `packages/ui/src/icons`,
`packages/ui/src/illustrations` and `apps/web-account/src/app/icon.svg`. Vector is
the right default here: the canvas is true black, the accents are declared as
custom properties a tenant can override, and a drawing that resolves its colours
at paint time follows that override without a rebuild. A PNG cannot.

This file covers the assets vector genuinely cannot do: two that still need
generating, with the prompt for each, and one already rendered from geometry we
own. Where a file has to land matters — the code that picks it up is already in
the repository — and the behaviour when it is absent differs per asset, which is
load-bearing for the grain. Both are given below.

## What is deliberately *not* here

Two obvious candidates were considered and dropped, so nobody generates them:

- **An OpenGraph card.** The root layout sets `robots: { index: false, follow:
  false }`, and it sets it for a reason an OG card cannot argue with: a crawler
  that follows a magic-link or verification URL consumes the token. A social
  preview for a surface nobody should be linking to is decoration with no reader.
- **Photographic imagery inside the account pages.** The pages already have a
  drawing layer, and it is a specific one: 2-unit contours, one accent per scene,
  flat fills on near-black. A rendered or photographed image dropped between two
  of those cards does not read as a richer version of the same thing — it reads as
  a different product's screenshot pasted in. Anything new that belongs *inside* a
  page belongs in `packages/ui/src/illustrations` as SVG.

---

## 1. Grain — `packages/ui/src/textures/grain-128.png`

**Why raster.** This is the one texture that has to be a bitmap. The alternative
is an SVG `feTurbulence`, and a full-viewport turbulence filter is recomposited on
every scroll and every resize — expensive enough to be visible on a mid-range
phone, for an effect measured in single-digit alpha. A 128×128 tile costs one
decode and is then handled by the compositor as a repeat.

**What it fixes.** The page headers are large, soft radial gradients on
`#000000`. Eight-bit-per-channel output cannot represent a smooth ramp that
close to black, so those washes band into visible rings on most panels. A few
percent of noise breaks the ramp up into dither and the rings disappear.

| | |
|---|---|
| Dimensions | 128 × 128 |
| Format | PNG-8 or PNG-24, greyscale + alpha |
| Weight | Under 8 KB. If it is larger, the noise is too fine-grained to tile |
| Must tile | Seamlessly, in both axes |

**Prompt**

> A seamless 128×128 tileable noise texture. Fine-grained monochrome film grain,
> evenly distributed, no visible clumps, streaks, scratches or dust specks. Neutral
> grey noise on a mid-grey field with no overall gradient, vignette or hot spots —
> the average brightness must be identical in every corner and at the centre.
> Grain particle size roughly 1–2 pixels. No pattern, no repetition artefacts, no
> visible seam when the image is tiled edge to edge. Flat, unlit, no texture
> beyond the grain itself. Output as a square image with no border and no
> watermark.

**After generating.** Convert to greyscale, then to alpha: the file must be
transparent where it is dark, so it can be laid over the page as `overlay`
without lifting the black point. Then check the tile by placing four copies in a
2×2 grid — if a seam or a bright quadrant shows, regenerate rather than trying to
patch it, since a patched tile fails in the other axis.

**Wiring.** Nothing references it yet, deliberately (see below). Once the file is
in place, add this to `packages/ui/src/styles/globals.css` beside the `body` rule
in Section 5:

```css
body::after {
  content: "";
  position: fixed;
  inset: 0;
  z-index: 9999;
  pointer-events: none;
  opacity: 0.035;
  background-image: url("../textures/grain-128.png");
  background-repeat: repeat;
}
```

`fixed` and not `absolute`: the grain is a property of the screen, not of the
document, and a grain that scrolls with a long settings page reads as a texture
printed on the content instead of as an imperfection in the display.
`pointer-events: none` is what keeps a full-viewport overlay from eating every
click on the page underneath it.

---

## 2. iOS home-screen icon — `apps/web-account/src/app/apple-icon.png`

**Already generated, and committed.** Listed here because it is raster and
because it has to be regenerated whenever the mark changes — not because it needs
a prompt. A flat two-colour shape is what a rasteriser is for; asking a generator
to approximate a glyph that already exists as geometry is how the two drift apart.

**Why raster at all.** iOS ignores an SVG for a home-screen bookmark. It is the
only mark in the set with no vector route.

**Source and regeneration.** The artboard is
`apps/web-account/design/apple-icon.svg` — square and frameless, because iOS masks
to a squircle it draws itself and a pre-rounded plaque gets cut twice. Its header
explains why it is a second artboard rather than `icon.svg` at another size, and
why it is parked outside `src/app`.

```bash
convert -background '#0a0a0c' -density 384 apps/web-account/design/apple-icon.svg -resize 180x180 -alpha remove -alpha off -depth 8 apps/web-account/src/app/apple-icon.png
```

`-density 384` rasterises at roughly 4× before the resize, so the curve is
downsampled rather than drawn at target size; `-alpha remove -alpha off` flattens
the transparency iOS does not want, and `-depth 8` stops ImageMagick from writing
a 16-bit file that is four times the size for no visible gain.

| | |
|---|---|
| Dimensions | 180 × 180 |
| Format | PNG-24, no alpha, 8-bit |
| Weight | 3.2 KB as generated |
| Corners | Square. iOS rounds them itself |

**One thing to watch when editing the artboard.** ImageMagick's SVG renderer
drops `stroke-opacity` and `fill-opacity` while honouring the colour beside them,
so a 28%-alpha hairline comes out as a solid ring. Both icon sources therefore
state pre-composited literals instead — keep it that way, or verify the render
rather than the source.

---

## 3. Sign-in backdrop — `apps/web-account/public/auth-backdrop.webp`

**Optional.** The sign-in and sign-up pages are one card on a black field, which
is a defensible look and is what ships today. This asset exists to make them feel
like a place rather than a modal with nothing behind it. Skip it and nothing
breaks.

**Why raster.** It is the one image on the platform whose value is in the parts
vector cannot cheaply carry: depth of field, volumetric falloff, and a gradient
soft enough over a large area that describing it as paths would be larger than
the bitmap.

| | |
|---|---|
| Dimensions | 1920 × 1080, generated at 2× and downsampled if the tool allows |
| Format | WebP, quality 72–80 |
| Weight | Under 180 KB. This loads before a reader has signed in, on whatever connection they have |
| Safe area | The middle 480 × 620 must be near-black and near-featureless — the card sits there, and detail behind it competes with the one input the page is asking them to fill |

**Prompt**

> An abstract dark background for a login screen, 1920×1080, landscape. Deep
> black field. Two very large, very soft out-of-focus light blooms in the far
> corners — one cool blue, one mint green — bleeding gently into the black and
> fading completely to pure black well before they reach the middle of the frame.
> The entire centre of the image is empty, flat, near-black, with no detail,
> texture or gradient. Extremely low contrast overall; the brightest point is no
> more than 12% grey. No objects, no shapes, no geometry, no grid, no lines, no
> stars, no lens flare, no text, no people, no logos. Smooth continuous falloff
> with no visible banding. Cinematic, quiet, minimal, unlit. No watermark.

**After generating.** Check the centre with an eyedropper before using it: a
generator asked for "empty" will often oblige with a faint gradient that is
invisible on a laptop and obvious on an OLED phone. If the centre is not within a
couple of levels of black, crush it before converting to WebP.

---

## Absent-file behaviour

This differs per asset, and the difference is why the grain is documented rather
than wired:

- **Grain.** A missing file here is a **build failure**, not a blank. Turbopack
  resolves `url()` in CSS at build time and errors on a path it cannot find —
  unlike an `<img>`, which merely 404s at runtime. So the CSS above stays out of
  the stylesheet until the PNG is in place. This is the one asset whose wiring
  cannot be committed ahead of the file. Compare `packages/ui/src/fonts`, whose
  `@font-face` rules *are* committed: the `.woff2` files there are gitignored but
  present locally, and a clone without them fails the same way.
- **`apple-icon.png`.** Committed, so this does not arise. Were it deleted, Next
  would emit no `<link rel="apple-touch-icon">` and iOS would fall back to a
  screenshot of the page. No error.
- **`auth-backdrop.webp`.** Absent, nothing references it at all. No error.

Unlike the fonts, these are our own artwork rather than licensed files, so they
belong in git once generated. Do not add them to `.gitignore`.
