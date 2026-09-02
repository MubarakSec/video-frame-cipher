# VFC Academic Kit — Design System

## Visual north star

An Arabic forensic cryptographic workbench built from hard edges, thin rules, disciplined spacing, exact byte grids, and a restrained signal-red accent. The lab feels instrument-like, not theatrical.

## Color strategy

Product surfaces use a **restrained** palette. Red marks the active layer, tampering, or the selected trace; tan marks derived/public teaching data; neutrals carry structure.

```css
--black: oklch(16% 0.005 90);        /* #0B0B0A */
--ink: oklch(21% 0.012 100);         /* #171713 */
--paper: oklch(91% 0.025 80);        /* #E9E1D1 */
--white: oklch(96.5% 0.018 85);      /* #F7F3E8 */
--tan: oklch(74% 0.08 75);           /* #C9AA75 */
--signal: oklch(58% 0.19 30);        /* #D43A2F */
--success: oklch(67% 0.12 145);
--warning: oklch(73% 0.12 75);
```

- Lab: black base, ink elevation steps, white text, tan derivation/evidence, red active trace/tamper state.
- No gradients. No transparent glass surfaces. Dark-mode depth comes from surface lightness and borders.

## Typography

- Arabic body/UI: **Noto Sans Arabic**, weights 400, 600, 700.
- Formal section headings: **Noto Kufi Arabic**, weights 600, 700.
- Hexadecimal, byte offsets, equations, and source identifiers: **JetBrains Mono** with LTR direction.
- Lab body: 1rem minimum; compact metadata may use 0.875rem.
- Five deliberate levels only: caption, secondary, body, subheading, display.

## Spacing and layout

- Four-point base scale: 4, 8, 12, 16, 24, 32, 48, 64, 96 px.
- Related controls: 8–12 px gaps. Distinct sections: 48–96 px.
- Lab: predictable CSS Grid, persistent rail on desktop, and a horizontal topic strip on narrow screens.
- Use cards only for truly self-contained interactive modules; prefer rules, columns, tables, and open grouping.
- Radii range from 0 to 12 px. Cryptographic matrices and data tables use 0–4 px.

## Visual language

- 4×4 state matrices are the recurring visual motif.
- Hairline rules, byte rulers, brackets, arrows, and numbered evidence notes replace decorative illustrations.
- Icons come from Lucide and are paired with Arabic labels where meaning may be ambiguous.
- Code-native SVG/CSS diagrams only in the final product.
- Monospace values always use `dir="ltr"` and aligned/tabular numerals.

## Motion

- Signature motion: a single trace pulse travels through the full pipeline when the user starts the guided trace.
- UI feedback: 100–150 ms; state transitions: 200–300 ms; panel/layout transitions: 300–450 ms.
- Ease: `cubic-bezier(0.25, 1, 0.5, 1)`.
- No page-load choreography and no staggered scroll reveals.
- Reduced-motion mode removes travel and uses immediate emphasis changes.

## Interaction rules

- Every control has default, hover, focus-visible, active, and disabled states.
- Tabs use semantic roles and arrow-key navigation where practical.
- Tooltips are supplementary; no essential information depends on hover.

## Responsive behavior

- Mobile: single-column lab, horizontal topic navigation, and matrices that preserve readable text.
- Tablet: two-column master/detail where room permits.
- Desktop: rail + primary inspector + evidence panel, constrained to a useful maximum width.
