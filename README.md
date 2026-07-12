# Rosetta 2 on Apple M5 miscomputes `ring`'s ChaCha20-Poly1305 (wrong output from 512-byte inputs)

`ring` 0.17's ChaCha20-Poly1305 returns the **wrong result for many message sizes ≥ 512 bytes**
when run as a `linux/amd64` binary under **Rosetta 2 on an Apple M5**. It's deterministic. Inputs
below 512 B are fine, and RustCrypto's ChaCha20-Poly1305 is fine at every size. On native arm64,
`ring` matches RustCrypto everywhere.

Silent correctness bug — no crash, just wrong ciphertext / failed tag verification. Any amd64
workload using `ring`'s ChaCha20-Poly1305 (rustls TLS, QUIC, Noise…) on an M5 via Rosetta is
affected.

**Cleanest proof:** under Rosetta, `ring` fails to reproduce a **published Google Wycheproof
test vector** (`chacha20_poly1305_test.json`, tcId 90, 513-byte plaintext) — it produces different
bytes than the vector's documented answer, while RustCrypto reproduces it exactly in the same run.
A published vector has one correct answer, so this needs no cross-implementation reasoning.

## The failure is block-count structured

The test seals identical inputs with **RustCrypto** (validated correct) and **`ring`** and diffs
them byte-for-byte across sizes. In 64-byte ChaCha20 blocks, under amd64 + Rosetta on M5:

| message size | blocks | ring vs RustCrypto |
|---|---|---|
| 64 – 448 B | 1 – 7 | ✅ match |
| **512 – 576 B** | **8 – 9** | ❌ **mismatch** (first failure at 512 B) |
| 640 – 832 B | 10 – 13 | ✅ match |
| **≥ 896 B** | **≥ 14** | ❌ mismatch (all sizes, incl. 2048, 4096, 8192) |

First failure is at exactly **512 B = 8 ChaCha20 blocks**. The size-structured pattern is
consistent with a vectorized code path being mistranslated, though we haven't identified the exact
instructions. The 2 KB Noise frame that started this sits squarely in the always-failing region.
This exact pattern is identical across every run.

## Reproduce

```
./run_verify amd64                                     # amd64 via Rosetta  → ring FAILS
./run_verify arm64                                     # native arm64       → all match
cargo run --release                                    # host               → all match
```

**`run_verify` usage** — run from the repo root with exactly one argument:

| command | what it does |
|---|---|
| `./run_verify amd64` | builds & runs the `linux/amd64` image (under Rosetta on Apple Silicon) — `ring` should FAIL |
| `./run_verify arm64` | builds & runs the `linux/arm64` image (native) — everything should PASS |

It just wraps `docker compose up --build` (amd64) and `docker compose -f docker-compose.arm64.yml
up --build` (arm64); any other argument prints usage and exits non-zero.

Output under amd64 + Rosetta on M5 (deterministic) — three parts, small → large → sweep:

```
arch = x86_64
--- published known-answer vector: SMALL input, 114 B (RFC 8439) ---
  PASS  RustCrypto (RFC 8439, 114B)
  PASS  ring       (RFC 8439, 114B)
--- published known-answer vector: LARGE input, 513 B (Google Wycheproof tcId 90) ---
  PASS  RustCrypto (Wycheproof tcId 90, 513B)   # correct answer
  FAIL  ring       (Wycheproof tcId 90, 513B)   # WRONG vs published vector
--- ring vs RustCrypto by message size ---
  FIRST MISMATCH at 512 bytes
  still-matching sizes: [64,128,192,256,320,384,448, 640,704,768,832]
```

On native arm64 the 513 B Wycheproof line reads `PASS` for both, and the sweep reports all-match.

## Scope

Tested on an **Apple M5 only.** We have **not** tested earlier Apple Silicon (M1–M4) or any other
CPU, so we can't say whether they are affected.

| config (Apple M5) | ring ChaCha20-Poly1305 |
|---|---|
| amd64 via **Rosetta** | ❌ wrong (deterministic; published vector + full sweep) |
| native **arm64** | ✅ correct |

The output `ring` fails to produce under Rosetta is the **published** Wycheproof vector — the same
bytes a correct implementation (including `ring` on real x86-64) must produce — so the fault is in
Rosetta's translation, not in `ring`'s source or the amd64 build. RustCrypto's ChaCha20-Poly1305
reproduces the published vectors in every configuration tested.

## Environment

Apple M5 (`Mac17,2`), macOS 26.5.2 (25F84); Docker Desktop 29.6.1, Apple Virtualization framework
with "Use Rosetta for x86_64/amd64 emulation" ON; `ring 0.17.14`. Verified on macOS 26.5.2.

## Workaround

Avoid Rosetta on M5: run **native arm64**, or route amd64 through **QEMU** instead (untick "Use
Rosetta…", or use the Docker VMM backend). Either way the affected Rosetta translation is not used.

---

<sub>Found via a Noise-protocol app (`hyper-noise`/`tokio-noise`) whose 2 KB transport frames
failed to decrypt: `tokio-noise` enables `snow`'s `ring-accelerated` feature, so its cipher is
`ring`'s ChaCha20-Poly1305 — exactly the failing case above.</sub>
