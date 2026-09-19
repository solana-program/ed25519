# solana-ed25519-program: on-chain signature verification for Solana

A minimal Solana SBF program that re-verifies Ed25519 signatures on-chain using
the Curve25519 and SHA-512 syscalls.

## Motivation

The goal is to migrate the native [ed25519 precompile] to SBF so it can be
maintained and deployed like any other on-chain program. This prototype uses the
compact `public_key || signature || message` instruction layout described below.

Being a regular SBF program also unlocks CPI: another program can invoke this
one and act on the explicit pass/fail result, rather than relying on
`sysvar::instructions` inspection to confirm a parallel precompile instruction
succeeded.

[ed25519 precompile]: https://docs.solanalabs.com/runtime/programs#ed25519-program

## Syscalls used

| Syscall                     | Wrapper or entry point                                                                              |
| --------------------------- | --------------------------------------------------------------------------------------------------- |
| `sol_sha512`                | `solana_sha512_hasher::hashv`                                                                       |
| `sol_curve_group_op`        | `solana_curve25519::edwards::subtract_edwards` on the single-signature fallback path                 |
| `sol_curve_validate_point`  | Public-key preparation and selected malformed-input checks                                        |
| `sol_curve_multiscalar_mul` | Fixed two-term wrapper for individual verification; variable-size MSM for batches                  |

The benchmark's published Mollusk/Agave runtime does not register `sol_sha512`,
so the tests install a metered shim using `solana-sha512-hasher`. Deployment
requires a VM that enables the SHA-512 syscall.

## Instruction format

The program verifies a single signature. Instruction data is:

```text
[0 .. 32]     public key A (32 bytes)
[32 .. 96]    signature R‖S (64 bytes)
[96 ..]       message
```

The `verify` helper in `solana-ed25519-verify` builds this layout. The crate
also declares the program's canonical on-chain address via `declare_id!`,
exposed as `ID` and `id()`:

```rust
use solana_ed25519_verify::{verify, ID};

let instruction = verify(&ID, &public_key, &signature, message);
```

### Constraints

- **Verification criteria.** The program always applies [ZIP-215]: the
  cofactored equation `[8](S·B − H(R‖A‖M)·A − R) == identity`.
  Small-order and non-canonical points are accepted. Programs needing a
  different variant (e.g. `verify_strict`) should depend on the
  `solana-ed25519-verify` library directly (see
  [Verification criteria](#verification-criteria-library)).
- **No accounts.** The program takes no account arguments and returns
  `InvalidArgument` if any are supplied.
- **Minimum length.** Instruction data shorter than the 96-byte
  `A || R‖S` header is rejected with `InvalidInstructionData`.
- **Error surface.** Every signature-verification failure — malformed
  encoding, a small-order or non-canonical rejection, or a signature that
  simply doesn't verify — surfaces uniformly as `InvalidInstructionData`,
  regardless of the underlying cause. Callers needing to distinguish failure
  reasons should depend on `solana-ed25519-verify` directly and inspect the
  [`Ed25519VerifyError`](#error-handling-library) returned by
  `Ed25519Verifier::verify_signature`.

[ZIP-215]: https://zips.z.cash/zip-0215

## Verification criteria (library)

Ed25519 "validity" is not one definition — implementations differ on cofactoring,
non-canonical encodings, and small-order rejection (see Henry de Valence's
[It's 255:19AM]). The `solana-ed25519-verify` crate exposes these as independent
knobs via `VerificationCriteria`:

| Knob                   | Effect when enabled                                                                          | Extra curve syscalls                            |
| ---------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `cofactored`           | Use `[8](S·B − H·A − R) == identity` instead of the cofactorless `S·B − H·A − R == identity` | none; torsion lookup on the fallback difference |
| `require_canonical_a`  | Reject public keys whose `y`-coordinate is `≥ p`                                             | none                                            |
| `require_canonical_r`  | Reject signature `R` whose `y`-coordinate is `≥ p`                                           | none                                            |
| `reject_small_order_a` | Reject small-order (torsion) public keys                                                     | none on the successful path                    |
| `reject_small_order_r` | Reject small-order signature `R` values                                                      | none on the successful path                    |

The verifier first compares the computed point encoding with `R`. If they differ,
the default profile subtracts `R` and checks the resulting point. It tests this
canonical difference against the torsion encodings, replacing three doublings
with a lookup. This lookup is skipped when the initial comparison succeeds.

Small-order checks inspect compressed encodings directly, including valid
non-canonical aliases. Curve validity is enforced by the MSM, a match to the
computed valid point, or a fallback curve operation. Strict verification with
canonical `R` can reject a byte mismatch after a 159-CU point-validation syscall,
avoiding the 475-CU subtraction. These are syscall charges; surrounding SBF
instructions also contribute to the measured totals.

Canonical `S` (`S < L`) has no knob. Every profile worth targeting requires it
because accepting `S ≥ L` reintroduces signature malleability. The syscall
`sol_curve_multiscalar_mul` enforces it regardless, converting scalars through
`Scalar::from_canonical_bytes` and rejecting out-of-range values before any group
operation runs. Batch verification explicitly checks each original `S` before
forming weighted scalars, so aggregation cannot hide an out-of-range input.

```rust
use solana_ed25519_verify::{Ed25519Verifier, VerificationCriteria};

// Default: the ZIP-215 preset (cofactored).
let verifier = Ed25519Verifier::new();

// `ed25519-dalek`'s verify_strict semantics.
let strict = Ed25519Verifier::with_criteria(VerificationCriteria::dalek_verify_strict());

// Or compose a variant by overriding individual knobs.
let custom = Ed25519Verifier::with_criteria(VerificationCriteria {
    reject_small_order_a: true,
    ..VerificationCriteria::zip215()
});

// See "Error handling" below for the possible failure reasons.
verifier.verify_signature(&signature, &public_key, message)?;
```

Named presets:

| Preset                  | `cofactored` | `canonical_a` | `canonical_r` | `small_order_a` | `small_order_r` |
| ----------------------- | ------------ | ------------- | ------------- | --------------- | --------------- |
| `zip215()` (default)    | ✓            |               |               |                 |                 |
| `dalek_verify_strict()` |              |               | ✓             | ✓               | ✓               |

`dalek_verify_strict()` matches `ed25519_dalek::VerifyingKey::verify_strict`
exactly (cross-checked in the test suite), including the detail that a
non-canonically encoded public key `A` is _not_ rejected. Further presets
(libsodium, RFC 8032 / FIPS 186-5) can be added in follow-ups.

The on-chain program always applies the `zip215()` preset. A program needing a
different variant should depend on this crate directly and build an
`Ed25519Verifier` from the desired `VerificationCriteria`.

[It's 255:19AM]: https://hdevalence.ca/blog/2020-10-04-its-25519am/

`PreparedPublicKey` reuses public-key validation and syscall inputs for repeated
verification with the same key and criteria. `verify_and_prepare` verifies the
first signature while preparing the key; `prepare_public_key` prepares it
separately. Subsequent calls to `PreparedPublicKey::verify_signature` retain
individual verification semantics.

`verify_batch(&[BatchItem])` aggregates cofactored signatures without allocating,
in chunks of at most 32. Identical key encodings share one MSM term. Chunks below
3 signatures with a shared key, or 11 otherwise, use individual verification;
all cofactorless profiles, including strict mode, also verify individually.
The aggregate uses transcript-derived 128-bit weights and has a negligible
false-acceptance probability under the hash random-oracle assumption. Use
individual verification when an exact per-signature decision is required.

## Error handling (library)

`Ed25519Verifier::verify_signature` returns `Result<(), Ed25519VerifyError>`.
The library crate has no dependency on `solana-program-error` or any other
Solana-runtime error type — `Ed25519VerifyError` is a plain, dependency-free
enum, so consumers outside a Solana program aren't forced into a
Solana-specific type.

| Variant                 | Meaning                                                                |
| ----------------------- | ---------------------------------------------------------------------- |
| `NonCanonicalPublicKey` | `A`'s `y`-coordinate is `≥ p` (`require_canonical_a` only)             |
| `NonCanonicalR`         | `R`'s `y`-coordinate is `≥ p` (`require_canonical_r` only)             |
| `SmallOrderPublicKey`   | `A` is a small-order (torsion) point (`reject_small_order_a` only)     |
| `SmallOrderR`           | `R` is a small-order (torsion) point (`reject_small_order_r` only)     |
| `InvalidEncoding`       | `A` or `R` doesn't decode to a valid point, or `S` is non-canonical (`S ≥ L`) |
| `SignatureMismatch`     | Every input decoded successfully, but the equation doesn't hold        |

Individual verification lets the MSM check `A` and `S` together. Batch
verification checks the original `S` before aggregation. Both report the same
`InvalidEncoding` error for malformed scalar or point encodings.

The on-chain program collapses all of these to
`ProgramError::InvalidInstructionData` — see [Constraints](#constraints).

## Cargo features

`solana-ed25519-verify` has two independent features, both enabled by default:

| Feature       | Unlocks                                                         | Pulls in                                    |
| ------------- | --------------------------------------------------------------- | ------------------------------------------- |
| `verify`      | `Ed25519Verifier`, `PreparedPublicKey`, `BatchItem`, criteria and errors | `solana-curve25519`, `solana-sha512-hasher` |
| `instruction` | `verify()`, `id()`, `ID` (the client-side instruction builder)  | `solana-instruction`, `solana-address`      |

A pure client that only needs to construct instructions for CPI or a
transaction — and never verifies a signature itself — can depend on
`instruction` alone, without pulling in the curve/hash syscall wrappers:

```toml
solana-ed25519-verify = { version = "0.1.0", default-features = false, features = [
    "instruction",
] }
```

## Build and test

Stable Rust `1.93.1` is pinned in `rust-toolchain.toml`. Some make targets
also require the nightly Rust chain `nightly-2026-01-22`.

SBF builds default to **v3** through `SBF_ARCH` in the Makefile, including CI
builds. Pass `--arch v3` when invoking `cargo build-sbf` directly.

```sh
# Library unit and integration tests (host, no SBF toolchain required)
cargo test --manifest-path ed25519-verify/Cargo.toml

# SBF build only
cargo build-sbf --arch v3 --manifest-path program/Cargo.toml

# SBF build via Makefile
make build-sbf-program

# Confirm the pure-client configuration compiles without the curve/hash
# syscall wrappers
cargo check --manifest-path ed25519-verify/Cargo.toml --no-default-features --features instruction

# Host unit tests, then SBF integration tests via Mollusk
make test-program

# Print Mollusk compute-unit measurements for the SBF program
make cu-program
```

The Mollusk tests execute `target/deploy/solana_ed25519_program.so`. They skip
unless `SBF_OUT_DIR` is set. Because published Mollusk/Agave crates do not yet
register `sol_sha512`, `program/tests/mollusk.rs` installs a local SHA-512
syscall shim before loading the SBF program. A production/localnet VM must
register the real `sol_sha512` syscall instead.

## Compute units

The measurements below were collected on September 18, 2026, using an SBF v3
release build with `cargo-build-sbf 4.1.0`, platform-tools `v1.54` (Rust `1.89.0`),
Mollusk `0.13.1`, and the metered SHA-512 test syscall shim. They include execution
of the program wrapper and the syscall charges in that harness. These are
compute-unit measurements, not host execution times.

The signature corpus contains 32 cases: signing-key seeds `7`, `42`, `99`, and
`201`, each tested with the eight message lengths below. Ranges show the observed
minimum and maximum across those seeds. Encoding checks and scalar correction
can cause small differences between signatures of the same message length.

|     Message bytes | Default ZIP-215 CU |    Strict CU |
| ----------------: | -----------------: | -----------: |
|                 0 |              3,733 |        3,745 |
|                 1 |              3,733 |  3,745–3,767 |
|                38 |              3,742 |        3,754 |
|                47 |              3,746 |  3,758–3,780 |
|                48 |              3,747 |        3,759 |
|                49 |        3,747–3,748 |  3,759–3,760 |
|               128 |              3,787 |        3,799 |
|             1,024 |              4,235 |        4,247 |
| **32-case total** |        **121,881** |  **122,309** |
| **Mean per case** |       **3,808.78** | **3,822.16** |

The separate 38-byte signature fixture also consumes **3,742 CU** with ZIP-215
and **3,754 CU** with `VerificationCriteria::dalek_verify_strict()`. The strict
column was measured using a separate build of the same program wrapper with
that preset selected. The shipped program continues to use ZIP-215.

Other measured paths in the default ZIP-215 build:

| Test case                                        |                                 CU |
| ------------------------------------------------ | ---------------------------------: |
| Accepted small-order public-key fixture          |                              4,281 |
| Accepted torsion encodings, 14 cases             | 3,735–4,287 per case; 59,364 total |
| Tampered message / public key                    |                      4,292 / 4,293 |
| Non-canonical `S` or invalid public-key encoding |                         3,722 each |
| Unexpected accounts                              |                                 16 |
| Instruction shorter than 96 bytes                |                                 19 |

To reproduce the default program measurements:

```sh
cargo build-sbf --arch v3 --tools-version v1.54 --manifest-path program/Cargo.toml \
    --sbf-out-dir "$PWD/target/deploy" -- --locked
SBF_OUT_DIR="$PWD/target/deploy" cargo test --locked \
    -p solana-ed25519-program --test mollusk \
    -- --nocapture --test-threads=1
```

Changing the SBF toolchain, dependencies, or syscall cost model can change these
results. Compare builds using the same corpus and metered syscall shim.

For 32 signatures with 38-byte messages, separate local fixtures measured the
following costs, including parsing and setup. The prepared-key case includes
verifying the first signature with `verify_and_prepare`. Batch messages vary per
item, using seed 7 for a shared key or successive seeds for distinct keys.
These wrappers differ from the single-signature program above.

| Verification path | Individual CU | Optimized CU | CU saved |
| ----------------- | ------------: | -----------: | -------: |
| Strict, prepared key | 120,242 | 119,613 | 629 |
| ZIP-215 batch, shared key | 120,476 | 83,575 | 36,901 (30.6%) |
| ZIP-215 batch, distinct keys | 120,474 | 116,170 | 4,304 (3.6%) |

Small batches incur dispatch overhead even when they use individual checks.
Prepared-key setup becomes worthwhile at four signatures in the strict fixture.

With matched strict criteria (`dalek_verify_strict()` plus
`require_canonical_a: true`), the 38-byte fixture consumes **3,757 CU**, versus
**4,853 CU** for [brine-ed25519 0.9.3] with its strict feature: **22.6% less** using
the same SBF v3 toolchain and syscall metering. Brine's default policy differs
from ZIP-215, so those defaults are not a like-for-like semantic comparison.

[brine-ed25519 0.9.3]: https://github.com/zfedoran/brine-ed25519/tree/3683ee1720db99df8252ecbf5b2924e8ab37a851
