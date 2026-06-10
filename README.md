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

```text
[0]                   number of signatures (u8)
[1]                   padding, ignored
[2 .. 2 + 14*N]       N x Ed25519SignatureOffsets records (14 bytes each, LE)
[2 + 14*N ..]         payload: public keys, signatures, messages (order flexible)
```

Each offset record matches `Ed25519SignatureOffsets` exposed by this crate:

```text
[0..2]    signature_offset
[2..4]    signature_instruction_index
[4..6]    public_key_offset
[6..8]    public_key_instruction_index
[8..10]   message_data_offset
[10..12]  message_data_size
[12..14]  message_instruction_index
```

### Constraints

- **All instruction-index fields must be `u16::MAX`.** The native precompile
  uses this sentinel for the current instruction. An SBF program receives only
  its own instruction data; cross-instruction references require a future
  runtime change.
- **ZIP-215 verification.** The program uses the cofactored equation
  `[8](S·B − H(R‖A‖M)·A) == [8]R` with canonical `S`, following
  [ZIP-215](https://zips.z.cash/zip-0215). Small-order `R` and public-key
  points are not explicitly rejected — the cofactor multiplication makes them
  indistinguishable from the identity contribution and verification fails
  naturally for any signature not crafted for them. This is backward compatible
  with `ed25519_dalek::verify_strict`: every point accepted by dalek is also
  accepted here (dalek rejects small-order points outright, so no valid dalek
  signature is broken by the relaxed check).
- **Zero-signature payloads** are accepted only when the buffer is exactly the
  2-byte header.
- **No accounts.** The program takes no account arguments and returns
  `InvalidArgument` if any are supplied.

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
