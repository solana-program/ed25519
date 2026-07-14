# solana-ed25519-program: on-chain signature verification for Solana

A minimal Solana SBF program that re-verifies Ed25519 signatures on-chain using
the Curve25519 and SHA-512 syscalls.

## Motivation

The goal is to migrate the native [ed25519 precompile] to SBF so it can be
maintained and deployed like any other on-chain program. The instruction format
is intentionally identical to the precompile for current-instruction data, so
clients can reuse the standard Ed25519 instruction layout.

Being a regular SBF program also unlocks CPI: another program can invoke this
one and act on the explicit pass/fail result, rather than relying on
`sysvar::instructions` inspection to confirm a parallel precompile instruction
succeeded.

[ed25519 precompile]: https://docs.solanalabs.com/runtime/programs#ed25519-program

## Syscalls used

| Syscall | SDK wrapper |
|---|---|
| `sol_sha512` | `solana_sha512_hasher::hashv` |
| `sol_curve_group_op` | `solana_curve25519::edwards::multiply_edwards` |
| `sol_curve_multiscalar_mul` | `solana_curve25519::edwards::multiscalar_multiply_edwards` |

`sol_sha512` is not live on mainnet yet. The wrapper crate is published as
`solana-sha512-hasher`, and a local/custom VM must enable the SHA-512 syscall
feature before SBF execution will work.

## Instruction format

The program verifies a single signature. Instruction data is:

```text
[0]           verification variant selector (u8)
[1 .. 33]     public key A (32 bytes)
[33 .. 97]    signature R‖S (64 bytes)
[97 ..]       message
```

The `ed25519_verify_instruction` helper in `solana-ed25519-verify` builds this
layout. The variant byte selects which verification preset the program applies
(see [Verification criteria](#verification-criteria-library)):

```text
0    ZIP-215 (default)
1    ed25519-dalek verify_strict
```

### Constraints

- **Verification variant.** Selected by byte `[0]`. Unrecognized selectors are
  rejected with `InvalidInstructionData`. The default (`0`) is [ZIP-215]: the
  cofactored equation `[8](S·B − H(R‖A‖M)·A) == [8]R` with canonical `S`.
  Small-order and non-canonical points are accepted under ZIP-215 but rejected
  under the `verify_strict` variant.
- **No accounts.** The program takes no account arguments and returns
  `InvalidArgument` if any are supplied.
- **Minimum length.** Instruction data shorter than the 97-byte
  `variant || A || R‖S` header is rejected with `InvalidInstructionData`.

[ZIP-215]: https://zips.z.cash/zip-0215

## Verification criteria (library)

Ed25519 "validity" is not one definition — implementations differ on cofactoring,
non-canonical encodings, and small-order rejection (see Henry de Valence's
[It's 255:19AM]). The `solana-ed25519-verify` crate exposes these as independent
knobs via `VerificationCriteria`:

| Knob | Effect when enabled | Extra syscalls |
|---|---|---|
| `cofactored` | Use `[8](S·B − H·A − R) == identity` instead of the cofactorless `S·B − H·A − R == identity` | +1 `sol_curve_group_op` |
| `require_canonical_a` | Reject public keys whose `y`-coordinate is `≥ p` | none |
| `require_canonical_r` | Reject signature `R` whose `y`-coordinate is `≥ p` | none |
| `reject_small_order_a` | Reject small-order (torsion) public keys | +1 `sol_curve_group_op` |
| `reject_small_order_r` | Reject small-order signature `R` values | +1 `sol_curve_group_op` |
| `require_canonical_s` | Reject `S ≥ L` | none |

```rust
use solana_ed25519_verify::{Ed25519Verifier, VerificationCriteria};

// Default: the ZIP-215 preset (cofactored, canonical S required).
let verifier = Ed25519Verifier::new();

// `ed25519-dalek`'s verify_strict semantics.
let strict = Ed25519Verifier::with_criteria(VerificationCriteria::dalek_verify_strict());

// Or compose a variant by overriding individual knobs.
let custom = Ed25519Verifier::with_criteria(VerificationCriteria {
    reject_small_order_a: true,
    ..VerificationCriteria::zip215()
});
```

Named presets:

| Preset | `cofactored` | `canonical_a` | `canonical_r` | `small_order_a` | `small_order_r` | `canonical_s` |
|---|---|---|---|---|---|---|
| `zip215()` (default) | ✓ | | | | | ✓ |
| `dalek_verify_strict()` | | | ✓ | ✓ | ✓ | ✓ |

`dalek_verify_strict()` matches `ed25519_dalek::VerifyingKey::verify_strict`
exactly (cross-checked in the test suite), including the detail that a
non-canonically encoded public key `A` is *not* rejected. Further presets
(libsodium, RFC 8032 / FIPS 186-5) can be added in follow-ups.

The on-chain program exposes these two presets through the leading
[variant selector byte](#instruction-format) of its instruction data, so callers
can pick either without a separate program deployment.

[It's 255:19AM]: https://hdevalence.ca/blog/2020-10-04-its-25519am/

## Build and test

Stable Rust `1.93.1` is pinned in `rust-toolchain.toml`. Some make targets
also require the nightly Rust chain `nightly-2026-01-22`.

```sh
# Unit tests (host, no SBF toolchain required)
cargo test --manifest-path program/Cargo.toml

# SBF build only
cargo build-sbf --arch v2 --manifest-path program/Cargo.toml

# SBF build via Makefile
make build-sbf-program

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
