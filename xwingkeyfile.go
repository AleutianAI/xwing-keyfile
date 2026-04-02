// Copyright (c) 2026 Aleutian AI.
// SPDX-License-Identifier: MIT

// Package xwingkeyfile provides PEM serialization for X-Wing (X25519 + ML-KEM-768)
// hybrid KEM key pairs.
//
// X-Wing is a post-quantum/classical hybrid KEM defined in IETF
// draft-connolly-cfrg-xwing-kem-05 (final). This package defines a PEM-based
// file format for X-Wing keys, enabling interoperable key storage and exchange.
//
// # File Format
//
// The binary payload (before PEM base64 encoding) is:
//
//	Public key:  ALT1 (4B magic) + 0x01 (version) + pubKey (1216B) = 1221B
//	Private key: ALT1 (4B magic) + 0x81 (version) + seed (32B)    = 37B
//
// Private keys are stored as the 32-byte seed only. The full key pair is derived
// deterministically via SHAKE256 expansion per the X-Wing spec §5.2. This
// minimizes the cryptographic attack surface on disk.
//
// Version bytes use the high bit to distinguish key type: 0x01 = public,
// 0x81 = private. This prevents misuse if the PEM framing is stripped.
//
// Version bytes 0x01–0x7F are reserved for future public key formats;
// 0x81–0xFF are reserved for future private key formats.
//
// # Security
//
// Callers MUST zero any []byte returned by [MarshalPrivateKey] after writing it
// to disk. The returned slice contains private key material.
//
// Callers MUST zero the [32]byte seed returned by [UnmarshalPrivateKey] when done.
// Callers SHOULD also zero the input data slice passed to [UnmarshalPrivateKey],
// as it contains the base64-encoded seed.
//
// # Fingerprint Privacy
//
// The fingerprint returned by [Fingerprint] is a stable, deterministic hash of the
// public key. It functions as a pseudonymous identifier that can correlate activity
// across otherwise unlinkable contexts. Do not include fingerprints in cross-context
// logs or expose them to third parties without considering linkability implications.
//
// # Dependencies
//
// This package depends only on Cloudflare CIRCL (github.com/cloudflare/circl).
// It has no Aleutian-internal dependencies and can be independently audited.
package xwingkeyfile

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/xwing"
)

// Sentinel errors for programmatic error handling. All validation errors returned
// by unmarshal functions wrap one of these sentinels, enabling callers to use
// [errors.Is] instead of string matching.
var (
	// ErrNoPEMBlock indicates the input data does not contain a valid PEM block.
	ErrNoPEMBlock = errors.New("xwingkeyfile: no PEM block found")

	// ErrWrongPEMType indicates the PEM block type does not match the expected type.
	ErrWrongPEMType = errors.New("xwingkeyfile: wrong PEM block type")

	// ErrBadMagic indicates the first 4 bytes of the payload are not "ALT1".
	ErrBadMagic = errors.New("xwingkeyfile: wrong magic bytes")

	// ErrBadVersion indicates the version byte is not recognized.
	ErrBadVersion = errors.New("xwingkeyfile: unsupported file version")

	// ErrBadPayloadSize indicates the binary payload has an unexpected length.
	ErrBadPayloadSize = errors.New("xwingkeyfile: unexpected payload size")

	// ErrTrailingData indicates the PEM file contains data after the first block.
	ErrTrailingData = errors.New("xwingkeyfile: unexpected trailing data")

	// ErrInputTooLarge indicates the input data exceeds the maximum allowed size.
	ErrInputTooLarge = errors.New("xwingkeyfile: input too large")

	// ErrInvalidKey indicates the key bytes were rejected by the underlying
	// cryptographic library.
	ErrInvalidKey = errors.New("xwingkeyfile: invalid key")
)

// magic is the 4-byte file format identifier present at the start of every
// key file payload (before PEM encoding). ASCII "ALT1".
//
// Unexported to prevent accidental mutation. Use [GetMagic] to read.
var magic = [4]byte{0x41, 0x4C, 0x54, 0x31}

// GetMagic returns a copy of the 4-byte file format magic identifier ("ALT1").
func GetMagic() [4]byte {
	return magic
}

const (
	// PubKeyVersion is the version byte for public key files.
	// The value 0x01 indicates public key file format version 1.
	PubKeyVersion = byte(0x01)

	// PrivKeyVersion is the version byte for private key files.
	// The high bit (0x80) distinguishes private from public even without PEM
	// headers, so files remain self-describing if the PEM framing is stripped.
	PrivKeyVersion = byte(0x81)

	// PubKeyPayloadSize is the binary payload size inside the PEM block for
	// public keys: magic(4) + version(1) + pubKey(1216) = 1221.
	PubKeyPayloadSize = 1221

	// PrivKeyPayloadSize is the binary payload size inside the PEM block for
	// private keys: magic(4) + version(1) + seed(32) = 37.
	PrivKeyPayloadSize = 37

	// PEMTypePublicKey is the PEM block type for public key files.
	PEMTypePublicKey = "ALEUTIAN HYBRID KEM PUBLIC KEY"

	// PEMTypePrivateKey is the PEM block type for private key files.
	PEMTypePrivateKey = "ALEUTIAN HYBRID KEM PRIVATE KEY"

	// MaxInputSize is the maximum input size accepted by unmarshal functions.
	// PEM overhead for a 1221-byte payload is ~1700 bytes; 4096 provides margin.
	MaxInputSize = 4096

	// xwingPubKeySize is the canonical X-Wing public key size in bytes:
	// MLKEMPub(1184) || X25519Pub(32).
	xwingPubKeySize = 1216
)

// SeedFromPrivateKey extracts the 32-byte seed from a CIRCL X-Wing private key.
//
// # Description
//
// Calls priv.MarshalBinary() and validates the result is exactly 32 bytes.
// This centralizes the assumption about CIRCL's private key serialization format
// so it can be updated in one place if CIRCL's API changes.
//
// # Inputs
//
//   - priv: An X-Wing private key implementing [kem.PrivateKey] from CIRCL.
//
// # Outputs
//
//   - [32]byte: The private key seed. Callers MUST zero this when done.
//   - error: Non-nil if the private key cannot be marshaled or has unexpected size.
//
// # Example
//
//	_, priv, _ := xwing.Scheme().GenerateKeyPair()
//	seed, err := xwingkeyfile.SeedFromPrivateKey(priv)
//	if err != nil {
//	    return err
//	}
//	defer func() { seed = [32]byte{} }()
//
// # Limitations
//
//   - Assumes CIRCL's MarshalBinary returns the 32-byte seed as the canonical
//     private key representation. If a future CIRCL version changes this layout,
//     the length check will fail loudly rather than silently misinterpreting bytes.
//   - The intermediate []byte from MarshalBinary is zeroed, but Go's garbage
//     collector may have already copied it during heap allocation.
//
// # Assumptions
//
//   - priv was produced by xwing.Scheme().GenerateKeyPair() or DeriveKeyPair().
//   - CIRCL's X-Wing PrivateKey.MarshalBinary() returns exactly 32 bytes (the seed).
func SeedFromPrivateKey(priv kem.PrivateKey) ([32]byte, error) {
	var seed [32]byte
	if priv == nil {
		return seed, fmt.Errorf("%w: private key is nil", ErrInvalidKey)
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return seed, fmt.Errorf("%w: marshal private key: %v", ErrInvalidKey, err)
	}
	if len(privBytes) != 32 {
		return seed, fmt.Errorf("%w: expected 32-byte seed from MarshalBinary, got %d bytes", ErrInvalidKey, len(privBytes))
	}

	copy(seed[:], privBytes)

	// Zero the intermediate slice returned by MarshalBinary.
	for i := range privBytes {
		privBytes[i] = 0
	}

	return seed, nil
}

// MarshalPublicKey serializes an X-Wing public key to PEM format.
//
// # Description
//
// Constructs a binary payload of magic(4) + version(1) + pubKey(1216) = 1221
// bytes, then wraps it in a PEM block with type "ALEUTIAN HYBRID KEM PUBLIC KEY".
// The pubKey bytes are in canonical X-Wing order: MLKEMPub(1184) || X25519Pub(32).
//
// # Inputs
//
//   - pub: An X-Wing public key implementing [kem.PublicKey] from CIRCL.
//     Must marshal to exactly 1216 bytes.
//
// # Outputs
//
//   - []byte: PEM-encoded public key file contents, suitable for os.WriteFile.
//   - error: Non-nil if the public key cannot be marshaled or has wrong size.
//
// # Example
//
//	scheme := xwing.Scheme()
//	pub, _, err := scheme.GenerateKeyPair()
//	if err != nil {
//	    return err
//	}
//	pemData, err := xwingkeyfile.MarshalPublicKey(pub)
//	if err != nil {
//	    return err
//	}
//	if err := os.WriteFile("keys.pub", pemData, 0644); err != nil {
//	    return err
//	}
//
// # Assumptions
//
//   - pub was generated by a compliant X-Wing implementation (CIRCL or compatible).
func MarshalPublicKey(pub kem.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: public key is nil", ErrInvalidKey)
	}

	raw, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: marshal public key: %v", ErrInvalidKey, err)
	}
	if len(raw) != xwingPubKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrBadPayloadSize, xwingPubKeySize, len(raw))
	}

	payload := make([]byte, PubKeyPayloadSize)
	copy(payload[0:4], magic[:])
	payload[4] = PubKeyVersion
	copy(payload[5:], raw)

	block := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: payload,
	}
	return pem.EncodeToMemory(block), nil
}

// MarshalPrivateKey serializes an X-Wing private key seed to PEM format.
//
// # Description
//
// Constructs a binary payload of magic(4) + version(1) + seed(32) = 37 bytes,
// then wraps it in a PEM block with type "ALEUTIAN HYBRID KEM PRIVATE KEY".
//
// Only the 32-byte seed is stored. The full key pair can be re-derived via
// xwing.Scheme().DeriveKeyPair(seed[:]).
//
// # Inputs
//
//   - seed: The 32-byte X-Wing private key seed. This is the canonical private
//     key representation per IETF draft-connolly-cfrg-xwing-kem-05 §5.2.
//
// # Outputs
//
//   - []byte: PEM-encoded private key file contents, suitable for
//     os.WriteFile(path, data, 0600).
//   - error: Reserved for future validation (e.g., seed entropy checks).
//     Currently always nil.
//
// # Example
//
//	seed, err := xwingkeyfile.SeedFromPrivateKey(priv)
//	if err != nil {
//	    return err
//	}
//	pemData, err := xwingkeyfile.MarshalPrivateKey(seed)
//	if err != nil {
//	    return err
//	}
//	if err := os.WriteFile("keys.priv", pemData, 0600); err != nil {
//	    return err
//	}
//	// MUST zero pemData after write:
//	for i := range pemData { pemData[i] = 0 }
//
// # Limitations
//
//   - The returned []byte contains private key material. Callers MUST zero it
//     after writing to disk.
//   - encoding/pem creates internal buffers that cannot be zeroed from user code.
//     This is a known limitation of Go's memory model.
//
// # Assumptions
//
//   - seed is a cryptographically random 32-byte value (or derived from one).
func MarshalPrivateKey(seed [32]byte) ([]byte, error) {
	payload := make([]byte, PrivKeyPayloadSize)
	copy(payload[0:4], magic[:])
	payload[4] = PrivKeyVersion
	copy(payload[5:], seed[:])

	block := &pem.Block{
		Type:  PEMTypePrivateKey,
		Bytes: payload,
	}
	result := pem.EncodeToMemory(block)

	// Zero the intermediate payload buffer. The seed bytes were copied into it
	// and must not linger in memory. Note: the Go compiler does not currently
	// optimize away this loop, but the Go spec does not guarantee this.
	for i := range payload {
		payload[i] = 0
	}

	return result, nil
}

// UnmarshalPublicKey parses a PEM-encoded X-Wing public key file.
//
// # Description
//
// Decodes the PEM block, validates the block type, magic bytes, version byte,
// and payload size, then parses the public key using CIRCL's X-Wing scheme.
// Rejects input larger than [MaxInputSize] and trailing data after the PEM block.
//
// # Inputs
//
//   - data: Raw bytes of the PEM-encoded public key file (as read by os.ReadFile).
//     Must not exceed [MaxInputSize] (4096 bytes).
//
// # Outputs
//
//   - kem.PublicKey: The parsed X-Wing public key, usable with CIRCL's
//     xwing.Scheme() for encapsulation.
//   - error: Non-nil if validation fails. Wraps one of the sentinel errors
//     ([ErrNoPEMBlock], [ErrWrongPEMType], [ErrBadPayloadSize], [ErrBadMagic],
//     [ErrBadVersion], [ErrTrailingData], [ErrInputTooLarge], [ErrInvalidKey])
//     for programmatic handling via [errors.Is].
//
// # Example
//
//	data, err := os.ReadFile("keys.pub")
//	if err != nil {
//	    return err
//	}
//	pub, err := xwingkeyfile.UnmarshalPublicKey(data)
//	if err != nil {
//	    return err
//	}
//	ct, ss, err := xwing.Scheme().Encapsulate(pub)
func UnmarshalPublicKey(data []byte) (kem.PublicKey, error) {
	if len(data) > MaxInputSize {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrInputTooLarge, len(data), MaxInputSize)
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return nil, ErrNoPEMBlock
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: %d bytes after PEM block", ErrTrailingData, len(rest))
	}
	if block.Type != PEMTypePublicKey {
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrWrongPEMType, PEMTypePublicKey, block.Type)
	}
	if len(block.Bytes) != PubKeyPayloadSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrBadPayloadSize, PubKeyPayloadSize, len(block.Bytes))
	}

	var fileMagic [4]byte
	copy(fileMagic[:], block.Bytes[0:4])
	if fileMagic != magic {
		return nil, ErrBadMagic
	}

	version := block.Bytes[4]
	if version != PubKeyVersion {
		return nil, fmt.Errorf("%w: 0x%02x", ErrBadVersion, version)
	}

	pub, err := xwing.Scheme().UnmarshalBinaryPublicKey(block.Bytes[5:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return pub, nil
}

// UnmarshalPrivateKey parses a PEM-encoded X-Wing private key file.
//
// # Description
//
// Decodes the PEM block, validates the block type, magic bytes, version byte,
// and payload size, then extracts the 32-byte seed. Zeros the PEM decode buffer
// after extracting the seed.
//
// The caller can derive the full key pair from the seed via
// xwing.Scheme().DeriveKeyPair(seed[:]).
//
// # Inputs
//
//   - data: Raw bytes of the PEM-encoded private key file (as read by os.ReadFile).
//     Must not exceed [MaxInputSize] (4096 bytes). Callers SHOULD zero this
//     slice after calling UnmarshalPrivateKey, as it contains the base64-encoded
//     seed.
//
// # Outputs
//
//   - [32]byte: The private key seed. Callers MUST zero this when done.
//   - error: Non-nil if validation fails. Wraps sentinel errors as with
//     [UnmarshalPublicKey].
//
// # Example
//
//	data, err := os.ReadFile("keys.priv")
//	if err != nil {
//	    return err
//	}
//	seed, err := xwingkeyfile.UnmarshalPrivateKey(data)
//	if err != nil {
//	    return err
//	}
//	defer func() { seed = [32]byte{} }() // zero seed when done
//	// Also zero the file data:
//	for i := range data { data[i] = 0 }
//	pub, priv := xwing.Scheme().DeriveKeyPair(seed[:])
func UnmarshalPrivateKey(data []byte) ([32]byte, error) {
	var seed [32]byte

	if len(data) > MaxInputSize {
		return seed, fmt.Errorf("%w: %d bytes (max %d)", ErrInputTooLarge, len(data), MaxInputSize)
	}

	block, rest := pem.Decode(data)
	if block == nil {
		return seed, ErrNoPEMBlock
	}
	if len(rest) > 0 {
		return seed, fmt.Errorf("%w: %d bytes after PEM block", ErrTrailingData, len(rest))
	}
	if block.Type != PEMTypePrivateKey {
		// Zero the decode buffer before returning — it may contain the seed.
		for i := range block.Bytes {
			block.Bytes[i] = 0
		}
		return seed, fmt.Errorf("%w: expected %q, got %q", ErrWrongPEMType, PEMTypePrivateKey, block.Type)
	}
	if len(block.Bytes) != PrivKeyPayloadSize {
		// Zero the decode buffer before returning — it may contain the seed.
		for i := range block.Bytes {
			block.Bytes[i] = 0
		}
		return seed, fmt.Errorf("%w: expected %d bytes, got %d", ErrBadPayloadSize, PrivKeyPayloadSize, len(block.Bytes))
	}

	var fileMagic [4]byte
	copy(fileMagic[:], block.Bytes[0:4])
	if fileMagic != magic {
		// Zero the decode buffer before returning — it contains the seed.
		for i := range block.Bytes {
			block.Bytes[i] = 0
		}
		return seed, ErrBadMagic
	}

	version := block.Bytes[4]
	if version != PrivKeyVersion {
		// Zero the decode buffer before returning — it contains the seed.
		for i := range block.Bytes {
			block.Bytes[i] = 0
		}
		return seed, fmt.Errorf("%w: 0x%02x", ErrBadVersion, version)
	}

	copy(seed[:], block.Bytes[5:])

	// Zero the PEM decode buffer. The seed bytes were copied out and must not
	// linger in the heap. This brings the unmarshal path to parity with
	// MarshalPrivateKey's payload zeroing.
	for i := range block.Bytes {
		block.Bytes[i] = 0
	}

	return seed, nil
}

// Fingerprint returns the 16-hex-char fingerprint of an X-Wing public key.
//
// # Description
//
// Computes the first 8 bytes of SHA-512(pubKeyBytes) where pubKeyBytes is the
// canonical 1216-byte representation (MLKEMPub || X25519Pub), rendered as
// lowercase hexadecimal (16 characters, zero-padded).
//
// The fingerprint covers both components of the hybrid key. If only the ML-KEM
// component were hashed, an attacker who substituted the X25519 component
// (e.g., with a low-order point) would not be detected.
//
// # Inputs
//
//   - pub: An X-Wing public key implementing [kem.PublicKey] from CIRCL.
//
// # Outputs
//
//   - string: 16-character lowercase hex fingerprint (64 bits of SHA-512).
//     Always exactly 16 characters, zero-padded.
//   - error: Non-nil if the public key cannot be marshaled.
//
// # Example
//
//	fp, err := xwingkeyfile.Fingerprint(pub)
//	if err != nil {
//	    return err
//	}
//	fmt.Fprintf(os.Stderr, "Public key fingerprint: %s\n", fp)
//
// # Limitations
//
//   - 64 bits provides collision resistance for human-readable display only,
//     not cryptographic binding. Do not use as a unique identifier in protocols.
//   - The fingerprint is a stable pseudonymous identifier. Do not include it in
//     cross-context logs or expose it to third parties without considering
//     linkability implications (see package-level doc).
func Fingerprint(pub kem.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("%w: public key is nil", ErrInvalidKey)
	}

	raw, err := pub.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("%w: marshal public key: %v", ErrInvalidKey, err)
	}

	h := sha512.Sum512(raw)
	return hex.EncodeToString(h[:8]), nil
}
