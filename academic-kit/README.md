# VFC Interactive Cryptography Lab

A teacher-ready Arabic lab for the VFC v0.2 cryptography project. It combines a guided explanation path with implementation-backed inspectors for the frame fingerprint, key derivation, SPN rounds, CBC, HMAC payload, audio embedding, and recorded evidence.

The React interface does not reimplement or simulate the cipher. `npm run trace` executes `../generate_vfc_trace.py`, which imports the real `../vfc/*.py` modules and writes the exact public teaching vector to `src/data/vfc-trace.ts`.

```bash
npm install
npm run dev
```

Production verification:

```bash
npm run check
cd .. && python3 -m vfc.tests
```

`predev` and `prebuild` regenerate the implementation trace automatically. See [README_AR.md](./README_AR.md) for Arabic usage, [PRODUCT.md](./PRODUCT.md) for scope, and [DESIGN.md](./DESIGN.md) for the visual system.

Security note: the deterministic password, salt, IV, keys, and measurements shown in the interface are public teaching data. VFC v0.2 is an educational custom construction, not production cryptography.
