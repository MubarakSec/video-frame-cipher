# VFC Academic Kit — Product Brief

## Register

Primary register: **product**. The only surface is an interactive teaching and evaluation lab.

## Platform and contexts

- Responsive web application, Arabic first and RTL by default.
- Desktop classroom/projector use for live explanation.
- Laptop/tablet use for inspection and discussion.
- Keyboard, mouse, and touch input; offline-capable after installation.

## Users

1. A cryptography instructor evaluating whether the design is understood and implemented honestly.
2. A student presenting VFC and answering technical questions under time pressure.
3. A reviewer who wants to connect every visual claim to real source code or generated evidence.

## Core purpose

Make the VFC v0.2 cryptographic layer understandable, inspectable, and presentable without overstating its security. The kit must show how the real implementation moves from a video-frame fingerprint through key derivation, the educational SPN cipher, CBC, HMAC-authenticated payload construction, and PCM audio LSB embedding.

## Content sources of truth

- `../VFC_CRYPTOGRAPHY_GUIDE_AR.md`
- `../generate_vfc_trace.py`
- `../vfc/*.py`
- The generated `src/data/vfc-trace.ts` teaching vector

No cryptographic state, key, measurement, or test result may be invented in the UI.

## Product principles

1. **Implementation-backed.** Exact byte values and measurements come from the Python trace generator.
2. **Cryptography first.** Explain key separation, reversibility, diffusion, chaining, authentication, and failure order before discussing visual polish.
3. **Causality over decoration.** Visuals must reveal what changes, why it changes, and what the next layer consumes.
4. **Academic honesty.** Clearly separate demonstration evidence from security proof and educational design from production cryptography.
5. **Single-surface focus.** Direct navigation and the guided path use the same verified lab sections.
6. **Progressive disclosure.** Begin with the system path, then expose bytes, equations, and code references when the reviewer asks.

## Primary surface

- **Cryptography lab:** interactive inspectors for fingerprint, KDF, SPN rounds, avalanche, CBC, payload, and audio embedding.
- **Guided explanation:** a six-stop path inside the lab that supplies a talking point and a concrete demonstration action.

## Accessibility target

- WCAG 2.2 AA contrast and visible focus states.
- Semantic headings, tables, buttons, labels, and status text.
- 44×44 px minimum touch targets.
- Full keyboard operation for navigation, tabs, matrices, and media controls.
- `prefers-reduced-motion` support.
- Layout remains usable at 200% zoom and down to 320 px.
- Color is never the only carrier of meaning.

## Anti-references

- Cyberpunk/HUD styling, neon “hacker” clichés, lock-and-shield clip art.
- Generic SaaS card grids, glassmorphism, gradients, floating pills, and decorative metrics.
- Fake terminal output, fabricated graphs, or random hexadecimal decoration.
- Hiding caveats, calling the custom cipher “secure like AES,” or treating 13 passing tests as a proof of security.
- Motion everywhere; animation must explain state or navigation.
