# xwing-keyfile

A Go library for [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) hybrid KEM key file serialization. X-Wing combines X25519 (classical) and ML-KEM-768 (post-quantum) into a single key encapsulation mechanism. This package defines a PEM file format for X-Wing key pairs and provides functions to marshal, unmarshal, and fingerprint keys. It depends only on [Cloudflare CIRCL](https://github.com/cloudflare/circl) and the Go standard library.

## Install

```
go get github.com/AleutianAI/xwing-keyfile
```

## Usage

```go
package main

import (
    "fmt"
    "os"

    xwingkeyfile "github.com/AleutianAI/xwing-keyfile"
    "github.com/cloudflare/circl/kem/xwing"
)

func main() {
    scheme := xwing.Scheme()

    // Generate a key pair.
    pub, priv, err := scheme.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Extract the 32-byte seed (canonical X-Wing private key).
    seed, err := xwingkeyfile.SeedFromPrivateKey(priv)
    if err != nil {
        panic(err)
    }

    // Write public key file.
    pubPEM, err := xwingkeyfile.MarshalPublicKey(pub)
    if err != nil {
        panic(err)
    }
    if err := os.WriteFile("keys.pub", pubPEM, 0644); err != nil {
        panic(err)
    }

    // Write private key file.
    privPEM, err := xwingkeyfile.MarshalPrivateKey(seed)
    if err != nil {
        panic(err)
    }
    if err := os.WriteFile("keys.priv", privPEM, 0600); err != nil {
        panic(err)
    }

    // Zero private key material after use.
    for i := range privPEM { privPEM[i] = 0 }
    seed = [32]byte{}

    // Print fingerprint.
    fp, err := xwingkeyfile.Fingerprint(pub)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Public key fingerprint: %s\n", fp)
}
```

### Reading key files

```go
// Read and parse a public key.
data, err := os.ReadFile("keys.pub")
if err != nil {
    return err
}
pub, err := xwingkeyfile.UnmarshalPublicKey(data)
if err != nil {
    return err
}

// Read and parse a private key (returns 32-byte seed).
data, err = os.ReadFile("keys.priv")
if err != nil {
    return err
}
seed, err := xwingkeyfile.UnmarshalPrivateKey(data)
if err != nil {
    return err
}
defer func() { seed = [32]byte{} }() // zero when done
for i := range data { data[i] = 0 }  // zero file data too

// Re-derive the full key pair from the seed.
pub, priv := xwing.Scheme().DeriveKeyPair(seed[:])
```

### Error handling

All validation errors wrap sentinel errors for programmatic handling:

```go
import "errors"

_, err := xwingkeyfile.UnmarshalPublicKey(data)
if errors.Is(err, xwingkeyfile.ErrBadMagic) {
    // Wrong file format
}
if errors.Is(err, xwingkeyfile.ErrBadVersion) {
    // Unsupported file version
}
```

Available sentinels: `ErrNoPEMBlock`, `ErrWrongPEMType`, `ErrBadMagic`, `ErrBadVersion`, `ErrBadPayloadSize`, `ErrTrailingData`, `ErrInputTooLarge`, `ErrInvalidKey`.

## Independent Key Generation

You do not need this package to generate X-Wing keys. Any implementation that produces the correct 1216-byte public key is compatible.

### Using Cloudflare CIRCL directly

```go
import "github.com/cloudflare/circl/kem/xwing"

scheme := xwing.Scheme()
pub, priv, _ := scheme.GenerateKeyPair()
pubBytes, _ := pub.MarshalBinary() // 1216 bytes
```

### Using a fixed seed (deterministic)

```go
seed := make([]byte, 32)
// Fill seed from your own entropy source (HSM, dice rolls, etc.)
pub, priv := xwing.Scheme().DeriveKeyPair(seed)
```

### From any ML-KEM-768 + X25519 implementation

The public key is the concatenation:

```
pubKey = MLKEMPub (1184 bytes) || X25519Pub (32 bytes)
```

Where `MLKEMPub` is the ML-KEM-768 encapsulation key (FIPS 203) and `X25519Pub` is the X25519 public key (RFC 7748).

## Test Vectors

The `testdata/vectors.json` file contains known-answer test vectors generated with Cloudflare CIRCL v1.6.3 against IETF draft-connolly-cfrg-xwing-kem-05 (final). Each vector specifies a seed, the expected public key bytes, and the expected fingerprint. Use these vectors to verify your implementation produces identical output.

**Warning:** The test vector seeds are public data. Never use them as real private keys.

## Security

- Private key files should be written with `0600` permissions.
- Zero `[]byte` slices containing private key material after use.
- Zero the input `data` slice after calling `UnmarshalPrivateKey` — it contains the base64-encoded seed.
- `MarshalPrivateKey` zeros its internal payload buffer. `UnmarshalPrivateKey` zeros the PEM decode buffer after extracting the seed, including on error paths.
- `encoding/pem` and `encoding/base64` create internal buffers that cannot be zeroed from user code. This is a known Go limitation. For high-assurance environments, consider `mlockall` and disabling core dumps at the process level.
- Unmarshal functions reject input larger than 4096 bytes (`MaxInputSize`) and reject trailing data after the PEM block.

## Dependencies

- [Cloudflare CIRCL](https://github.com/cloudflare/circl) v1.6.3 — X-Wing KEM implementation
- Go standard library (`crypto/sha512`, `encoding/hex`, `encoding/pem`)

No other dependencies.

## License

MIT — see [LICENSE](LICENSE).

---

## Technical Reference

> The sections below cover the file format specification, the cryptographic rationale for X-Wing, and why this package exists. Skip this if you only need the API.

### Why X-Wing

RSA and ECDH key exchange are broken by a sufficiently large quantum computer running Shor's algorithm. This is not a current threat, but ciphertext recorded today can be decrypted later ("harvest now, decrypt later"). For long-lived secrets, the migration window is now.

NIST standardized ML-KEM (FIPS 203, August 2024) as the post-quantum KEM replacement. ML-KEM-768 targets NIST security level 3 (128-bit post-quantum security). However, ML-KEM is based on module lattices, a class of problems with less cryptanalytic history than RSA or elliptic curves. A lattice-specific breakthrough would leave ML-KEM-only systems exposed with no fallback.

X-Wing addresses this by combining ML-KEM-768 with X25519 in a single KEM. The combined scheme is secure if either component is secure. An attacker must break both ML-KEM-768 (lattice) and X25519 (ECDH) to recover the shared secret. This is the standard hedge: deploy post-quantum now, keep classical as insurance.

X-Wing is specified in [IETF draft-connolly-cfrg-xwing-kem-05](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) (final). It is a concrete, non-negotiable combination — no algorithm agility, no parameter selection. This reduces implementation risk.

### Why CIRCL

[Cloudflare CIRCL](https://github.com/cloudflare/circl) is the only production-grade Go implementation of X-Wing. It is maintained by Cloudflare's cryptography team, used in Cloudflare's TLS stack, and implements ML-KEM-768 per FIPS 203 and X25519 per RFC 7748. CIRCL's X-Wing implementation passes the IETF test vectors from the draft specification.

There is no Go standard library support for ML-KEM-768 or X-Wing as of Go 1.25. `crypto/mlkem` provides ML-KEM but not the X-Wing combiner. CIRCL is the pragmatic choice.

CIRCL is not FIPS-certified. For environments requiring FIPS 140-3 validation, the Go BoringCrypto build constraint provides FIPS-validated primitives, but does not cover ML-KEM or X-Wing. This is a known gap across the industry — no FIPS-validated X-Wing implementation exists as of 2026.

### Why this package

CIRCL provides the KEM operations (keygen, encapsulate, decapsulate) but no file format. Keys exist only as in-memory Go types. This package solves the serialization problem: how to write keys to disk, read them back, and identify them.

The file format is intentionally minimal. PEM wrapping provides visual identification and copy-paste safety. The binary payload uses a 4-byte magic (`ALT1`) and a version byte to make files self-describing even without PEM headers. Private keys store only the 32-byte seed, not the expanded 2400-byte ML-KEM decapsulation key, because the expansion is deterministic (SHAKE256 per the X-Wing spec) and storing derived material increases attack surface for no benefit.

### File Format Specification

#### Public Key (`.pub`)

```
-----BEGIN ALEUTIAN HYBRID KEM PUBLIC KEY-----
<base64 of binary payload>
-----END ALEUTIAN HYBRID KEM PUBLIC KEY-----
```

**Binary payload (1221 bytes):**

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | Magic | `ALT1` (`0x41 0x4C 0x54 0x31`) |
| 4 | 1 | Version | `0x01` (public key file v1) |
| 5 | 1184 | ML-KEM-768 public key | `pk_M` per X-Wing spec |
| 1189 | 32 | X25519 public key | `pk_X` per X-Wing spec |

Field order matches the canonical X-Wing wire format: ML-KEM first, X25519 second.

#### Private Key (`.priv`)

```
-----BEGIN ALEUTIAN HYBRID KEM PRIVATE KEY-----
<base64 of binary payload>
-----END ALEUTIAN HYBRID KEM PRIVATE KEY-----
```

**Binary payload (37 bytes):**

| Offset | Size | Field | Value |
|--------|------|-------|-------|
| 0 | 4 | Magic | `ALT1` (`0x41 0x4C 0x54 0x31`) |
| 4 | 1 | Version | `0x81` (private key file v1) |
| 5 | 32 | Seed | X-Wing private key seed |

**Why store only the 32-byte seed?** The X-Wing spec (IETF draft-connolly-cfrg-xwing-kem-05, section 5.2) defines the canonical private key as a 32-byte seed. The full ML-KEM decapsulation key (2400 bytes) and X25519 scalar (32 bytes) are derived deterministically via SHAKE256:

```
expanded = SHAKE256(seed, 96)
mlkem_d  = expanded[0:32]    // ML-KEM-768 d parameter
mlkem_z  = expanded[32:64]   // ML-KEM-768 z parameter
x25519   = expanded[64:96]   // X25519 private scalar
```

Storing only the seed minimizes attack surface on disk and aligns with the spec.

#### Version Byte Convention

The high bit of the version byte distinguishes key type:

| Version | Meaning |
|---------|---------|
| `0x01` | Public key file, format version 1 |
| `0x81` | Private key file, format version 1 |
| `0x01`–`0x7F` | Reserved for future public key formats |
| `0x81`–`0xFF` | Reserved for future private key formats |

This ensures the binary payload is self-describing even without PEM headers.

#### Fingerprint

The fingerprint is the first 8 bytes of `SHA-512(pubKeyBytes)` rendered as 16 lowercase hex characters (zero-padded), where `pubKeyBytes` is the canonical 1216-byte public key (ML-KEM || X25519).

The fingerprint covers both components of the hybrid key. If only the ML-KEM component were hashed, substitution of the X25519 component (e.g., with a low-order point) would go undetected.

**Privacy note:** The fingerprint is a stable, deterministic identifier. It functions as a pseudonymous correlator — do not include it in cross-context logs or expose it to third parties without considering linkability implications.

#### Input Size Limits

Unmarshal functions reject input larger than 4096 bytes (`MaxInputSize`) and reject trailing data after the PEM block. This prevents denial-of-service via oversized inputs.
