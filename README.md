# solana-ed25519: on-chain signature verification for Solana

This workspace provides two crates:

- `solana-ed25519-verify`: a no-std, stateless Ed25519 verification library.
- `solana-ed25519-program`: a minimal Pinocchio SBF program that calls the
  library and returns an explicit pass/fail result.

Both use the Curve25519 and SHA-512 syscalls. The program entrypoint uses
Pinocchio's lazy instruction context to avoid up-front account parsing.

## Motivation

The goal is to migrate the native [ed25519 precompile] to SBF so it can be
maintained and deployed like any other on-chain program. The precompile is
expected to be removed from the runtime, so this program does not preserve
byte-for-byte compatibility with its instruction format: since an SBF program
only ever receives its own instruction data, the precompile's
cross-instruction reference fields have no meaning here and are dropped
entirely, giving a more compact encoding.

Programs can either depend on `solana-ed25519-verify` directly or invoke
`solana-ed25519-program` by CPI and act on the explicit pass/fail result,
rather than relying on `sysvar::instructions` inspection to confirm a parallel
precompile instruction succeeded.

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
[0]                  number of signatures (u8)
[1]                  padding, ignored
[2 .. 2 + 8*N]       N x SignatureOffsets records (8 bytes each, LE)
[2 + 8*N ..]         payload: public keys, signatures, messages (order flexible)
```

Each offset record matches `SignatureOffsets` exposed by this crate:

```text
[0..2]    signature_offset
[2..4]    public_key_offset
[4..6]    message_data_offset
[6..8]    message_data_size
```

Every offset implicitly refers to this instruction's own data. Unlike the
native precompile, there is no wire representation for referencing another
instruction in the transaction.

### Constraints

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

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `instruction` | off | Enables alloc-based `Instruction` construction helpers. |
| `dev-context-only-utils` | off | Enables `instruction` and exposes `test_utils`, the instruction builders shared by this crate's and `solana-ed25519-program`'s tests. |
| `serde` | off | Derives serde traits for `SignatureOffsets`. |

`solana-ed25519-program` only exposes `no-entrypoint`, which omits the
Pinocchio entrypoint when embedding the program crate in tests or another
program.

## Public API

`solana-ed25519-verify` exposes the stateless `Ed25519Verifier`, layout
constants, `SignatureOffsets`, and, with the `instruction` feature, fallible
instruction constructors `new_ed25519_instruction_with_signature` and
`offsets_to_ed25519_instruction`. Both constructors take the target
`program_id` explicitly, since this format is specific to wherever this
program (or one embedding this library) is deployed rather than the fixed
native precompile address.

`solana-ed25519-program` calls the library from its Pinocchio processor.

## Build and test

Stable Rust `1.93.1` is pinned in `rust-toolchain.toml`. Some make targets
also require the nightly Rust chain `nightly-2026-01-22`.

```sh
# Unit tests (host, no SBF toolchain required)
cargo test --workspace

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
