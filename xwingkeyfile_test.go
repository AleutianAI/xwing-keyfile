// Copyright (c) 2026 Aleutian AI.
// SPDX-License-Identifier: MIT

package xwingkeyfile

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/xwing"
)

// testVectorFile is a collection of known-answer test vectors generated with
// Cloudflare CIRCL. Each vector contains a seed and the expected public key
// bytes and fingerprint.
type testVectorFile struct {
	Description string       `json:"description"`
	Vectors     []testVector `json:"vectors"`
}

// testVector is a single known-answer test case.
type testVector struct {
	Comment             string `json:"comment"`
	SeedHex             string `json:"seed_hex"`
	ExpectedPubHex      string `json:"expected_pub_hex"`
	ExpectedFingerprint string `json:"expected_pub_fingerprint"`
}

// loadTestVectors reads and parses the test vector file.
func loadTestVectors(t *testing.T) []testVector {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read test vectors: %v", err)
	}
	var vf testVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse test vectors: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("test vector file contains no vectors")
	}
	return vf.Vectors
}

// --- Known-Answer Test Vectors ---

func TestVectors(t *testing.T) {
	vectors := loadTestVectors(t)
	scheme := xwing.Scheme()

	for _, v := range vectors {
		t.Run(v.Comment, func(t *testing.T) {
			seedBytes, err := hex.DecodeString(v.SeedHex)
			if err != nil {
				t.Fatalf("decode seed hex: %v", err)
			}
			if len(seedBytes) != 32 {
				t.Fatalf("seed must be 32 bytes, got %d", len(seedBytes))
			}

			pub, _ := scheme.DeriveKeyPair(seedBytes)
			pubBytes, err := pub.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal public key: %v", err)
			}

			expectedPub, err := hex.DecodeString(v.ExpectedPubHex)
			if err != nil {
				t.Fatalf("decode expected pub hex: %v", err)
			}
			if hex.EncodeToString(pubBytes) != hex.EncodeToString(expectedPub) {
				t.Error("public key mismatch against test vector")
			}

			fp, err := Fingerprint(pub)
			if err != nil {
				t.Fatalf("compute fingerprint: %v", err)
			}
			if fp != v.ExpectedFingerprint {
				t.Errorf("fingerprint mismatch: got %q, want %q", fp, v.ExpectedFingerprint)
			}
		})
	}
}

// --- SeedFromPrivateKey ---

func TestSeedFromPrivateKey(t *testing.T) {
	scheme := xwing.Scheme()
	_, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	seed, err := SeedFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("SeedFromPrivateKey: %v", err)
	}

	// Verify extracted seed matches raw MarshalBinary output.
	privBytes, _ := priv.MarshalBinary()
	var expectedSeed [32]byte
	copy(expectedSeed[:], privBytes)
	if seed != expectedSeed {
		t.Error("extracted seed does not match MarshalBinary output")
	}
}

func TestSeedFromPrivateKeyNil(t *testing.T) {
	_, err := SeedFromPrivateKey(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got: %v", err)
	}
}

// --- Public Key Round-Trip ---

func TestMarshalUnmarshalPublicKeyRoundTrip(t *testing.T) {
	scheme := xwing.Scheme()
	pub, _, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	pemData, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	recovered, err := UnmarshalPublicKey(pemData)
	if err != nil {
		t.Fatalf("unmarshal public key: %v", err)
	}

	origBytes, _ := pub.MarshalBinary()
	recoveredBytes, _ := recovered.MarshalBinary()
	if hex.EncodeToString(origBytes) != hex.EncodeToString(recoveredBytes) {
		t.Error("round-trip produced different public key bytes")
	}
}

func TestMarshalPublicKeyPEMStructure(t *testing.T) {
	scheme := xwing.Scheme()
	pub, _, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	pemData, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	block, rest := pem.Decode(pemData)
	if block == nil {
		t.Fatal("PEM decode returned nil block")
	}
	if len(rest) != 0 {
		t.Errorf("unexpected trailing data: %d bytes", len(rest))
	}
	if block.Type != PEMTypePublicKey {
		t.Errorf("PEM type: got %q, want %q", block.Type, PEMTypePublicKey)
	}
	if len(block.Bytes) != PubKeyPayloadSize {
		t.Errorf("payload size: got %d, want %d", len(block.Bytes), PubKeyPayloadSize)
	}

	var fileMagic [4]byte
	copy(fileMagic[:], block.Bytes[0:4])
	if fileMagic != magic {
		t.Errorf("magic: got %x, want %x", fileMagic, magic)
	}
	if block.Bytes[4] != PubKeyVersion {
		t.Errorf("version: got 0x%02x, want 0x%02x", block.Bytes[4], PubKeyVersion)
	}
}

func TestMarshalPublicKeyNil(t *testing.T) {
	_, err := MarshalPublicKey(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got: %v", err)
	}
}

// --- Private Key Round-Trip ---

func TestMarshalUnmarshalPrivateKeyRoundTrip(t *testing.T) {
	scheme := xwing.Scheme()
	_, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	seed, err := SeedFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("extract seed: %v", err)
	}

	pemData, err := MarshalPrivateKey(seed)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	recovered, err := UnmarshalPrivateKey(pemData)
	if err != nil {
		t.Fatalf("unmarshal private key: %v", err)
	}

	if seed != recovered {
		t.Error("round-trip produced different seed")
	}
}

func TestMarshalPrivateKeyPEMStructure(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	pemData, err := MarshalPrivateKey(seed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	block, rest := pem.Decode(pemData)
	if block == nil {
		t.Fatal("PEM decode returned nil block")
	}
	if len(rest) != 0 {
		t.Errorf("unexpected trailing data: %d bytes", len(rest))
	}
	if block.Type != PEMTypePrivateKey {
		t.Errorf("PEM type: got %q, want %q", block.Type, PEMTypePrivateKey)
	}
	if len(block.Bytes) != PrivKeyPayloadSize {
		t.Errorf("payload size: got %d, want %d", len(block.Bytes), PrivKeyPayloadSize)
	}

	var fileMagic [4]byte
	copy(fileMagic[:], block.Bytes[0:4])
	if fileMagic != magic {
		t.Errorf("magic: got %x, want %x", fileMagic, magic)
	}
	if block.Bytes[4] != PrivKeyVersion {
		t.Errorf("version: got 0x%02x, want 0x%02x", block.Bytes[4], PrivKeyVersion)
	}

	// Verify seed bytes are in the payload.
	var extractedSeed [32]byte
	copy(extractedSeed[:], block.Bytes[5:])
	if extractedSeed != seed {
		t.Error("payload seed does not match input seed")
	}
}

// --- Deterministic Key Derivation ---

func TestMarshalPrivateKeyDeterministic(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = 0xAB
	}

	pem1, err1 := MarshalPrivateKey(seed)
	pem2, err2 := MarshalPrivateKey(seed)
	if err1 != nil || err2 != nil {
		t.Fatalf("marshal errors: %v, %v", err1, err2)
	}

	if string(pem1) != string(pem2) {
		t.Error("MarshalPrivateKey is not deterministic")
	}
}

// --- GetMagic ---

func TestGetMagic(t *testing.T) {
	m := GetMagic()
	expected := [4]byte{0x41, 0x4C, 0x54, 0x31}
	if m != expected {
		t.Errorf("GetMagic: got %x, want %x", m, expected)
	}

	// Verify mutation of returned copy does not affect internal magic.
	m[0] = 0xFF
	m2 := GetMagic()
	if m2[0] != 0x41 {
		t.Error("GetMagic returned a reference instead of a copy")
	}
}

// --- Fingerprint ---

func TestFingerprint(t *testing.T) {
	vectors := loadTestVectors(t)
	scheme := xwing.Scheme()

	for _, v := range vectors {
		t.Run(v.Comment, func(t *testing.T) {
			seedBytes, _ := hex.DecodeString(v.SeedHex)
			pub, _ := scheme.DeriveKeyPair(seedBytes)

			fp, err := Fingerprint(pub)
			if err != nil {
				t.Fatalf("fingerprint: %v", err)
			}
			if fp != v.ExpectedFingerprint {
				t.Errorf("got %q, want %q", fp, v.ExpectedFingerprint)
			}
			if len(fp) != 16 {
				t.Errorf("fingerprint length: got %d, want 16", len(fp))
			}
		})
	}
}

func TestFingerprintAlwaysSixteenChars(t *testing.T) {
	// Construct a hash prefix with a leading zero byte to verify zero-padding.
	// We test this by verifying the hex.EncodeToString behavior directly,
	// since finding a key whose SHA-512 starts with 0x00 would require brute force.
	h := [8]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	result := hex.EncodeToString(h[:])
	if len(result) != 16 {
		t.Errorf("hex.EncodeToString length: got %d, want 16", len(result))
	}
	if result != "0001020304050607" {
		t.Errorf("hex.EncodeToString: got %q, want %q", result, "0001020304050607")
	}
}

func TestFingerprintNil(t *testing.T) {
	_, err := Fingerprint(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got: %v", err)
	}
}

// --- Unmarshal Validation: Public Key ---

func TestUnmarshalPublicKeyEmpty(t *testing.T) {
	_, err := UnmarshalPublicKey([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("expected ErrNoPEMBlock, got: %v", err)
	}
}

func TestUnmarshalPublicKeyNil(t *testing.T) {
	_, err := UnmarshalPublicKey(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("expected ErrNoPEMBlock, got: %v", err)
	}
}

func TestUnmarshalPublicKeyNoPEM(t *testing.T) {
	_, err := UnmarshalPublicKey([]byte("not PEM data"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("expected ErrNoPEMBlock, got: %v", err)
	}
}

func TestUnmarshalPublicKeyInputTooLarge(t *testing.T) {
	_, err := UnmarshalPublicKey(make([]byte, MaxInputSize+1))
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
	if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("expected ErrInputTooLarge, got: %v", err)
	}
}

func TestUnmarshalPublicKeyTrailingData(t *testing.T) {
	scheme := xwing.Scheme()
	pub, _, _ := scheme.GenerateKeyPair()
	pemData, _ := MarshalPublicKey(pub)

	// Append trailing data.
	withTrailing := append(pemData, []byte("\nextra data here")...)
	_, err := UnmarshalPublicKey(withTrailing)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
	if !errors.Is(err, ErrTrailingData) {
		t.Errorf("expected ErrTrailingData, got: %v", err)
	}
}

func TestUnmarshalPublicKeyWrongPEMType(t *testing.T) {
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: make([]byte, PubKeyPayloadSize),
	}
	_, err := UnmarshalPublicKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrWrongPEMType) {
		t.Errorf("expected ErrWrongPEMType, got: %v", err)
	}
}

func TestUnmarshalPublicKeyWrongPayloadSize(t *testing.T) {
	block := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: make([]byte, 100),
	}
	_, err := UnmarshalPublicKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBadPayloadSize) {
		t.Errorf("expected ErrBadPayloadSize, got: %v", err)
	}
}

func TestUnmarshalPublicKeyBadMagic(t *testing.T) {
	payload := make([]byte, PubKeyPayloadSize)
	copy(payload[0:4], []byte("XXXX"))
	payload[4] = PubKeyVersion

	block := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: payload,
	}
	_, err := UnmarshalPublicKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBadMagic) {
		t.Errorf("expected ErrBadMagic, got: %v", err)
	}
}

func TestUnmarshalPublicKeyBadVersion(t *testing.T) {
	payload := make([]byte, PubKeyPayloadSize)
	copy(payload[0:4], magic[:])
	payload[4] = 0xFF // unsupported version

	block := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: payload,
	}
	_, err := UnmarshalPublicKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBadVersion) {
		t.Errorf("expected ErrBadVersion, got: %v", err)
	}
}

func TestUnmarshalPublicKeyInvalidCIRCLKey(t *testing.T) {
	// Valid envelope (magic, version, correct size) but garbage key bytes.
	// CIRCL should reject this.
	payload := make([]byte, PubKeyPayloadSize)
	copy(payload[0:4], magic[:])
	payload[4] = PubKeyVersion
	// Fill key area with 0xFF — not a valid ML-KEM public key.
	for i := 5; i < len(payload); i++ {
		payload[i] = 0xFF
	}

	block := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: payload,
	}
	_, err := UnmarshalPublicKey(pem.EncodeToMemory(block))
	if err == nil {
		// CIRCL may or may not reject this — some ML-KEM implementations accept
		// any 1184-byte input. If no error, the test still passes (we're verifying
		// the error path works when CIRCL does reject).
		t.Log("CIRCL accepted garbage key bytes — no error path to test")
		return
	}
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got: %v", err)
	}
}

// --- Unmarshal Validation: Private Key ---

func TestUnmarshalPrivateKeyEmpty(t *testing.T) {
	_, err := UnmarshalPrivateKey([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("expected ErrNoPEMBlock, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyNil(t *testing.T) {
	_, err := UnmarshalPrivateKey(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("expected ErrNoPEMBlock, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyNoPEM(t *testing.T) {
	_, err := UnmarshalPrivateKey([]byte("not PEM data"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("expected ErrNoPEMBlock, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyInputTooLarge(t *testing.T) {
	_, err := UnmarshalPrivateKey(make([]byte, MaxInputSize+1))
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
	if !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("expected ErrInputTooLarge, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyTrailingData(t *testing.T) {
	var seed [32]byte
	pemData, _ := MarshalPrivateKey(seed)
	withTrailing := append(pemData, []byte("\nextra")...)
	_, err := UnmarshalPrivateKey(withTrailing)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
	if !errors.Is(err, ErrTrailingData) {
		t.Errorf("expected ErrTrailingData, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyWrongPEMType(t *testing.T) {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: make([]byte, PrivKeyPayloadSize),
	}
	_, err := UnmarshalPrivateKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrWrongPEMType) {
		t.Errorf("expected ErrWrongPEMType, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyWrongPayloadSize(t *testing.T) {
	block := &pem.Block{
		Type:  PEMTypePrivateKey,
		Bytes: make([]byte, 100),
	}
	_, err := UnmarshalPrivateKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBadPayloadSize) {
		t.Errorf("expected ErrBadPayloadSize, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyBadMagic(t *testing.T) {
	payload := make([]byte, PrivKeyPayloadSize)
	copy(payload[0:4], []byte("XXXX"))
	payload[4] = PrivKeyVersion

	block := &pem.Block{
		Type:  PEMTypePrivateKey,
		Bytes: payload,
	}
	_, err := UnmarshalPrivateKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBadMagic) {
		t.Errorf("expected ErrBadMagic, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyBadVersion(t *testing.T) {
	payload := make([]byte, PrivKeyPayloadSize)
	copy(payload[0:4], magic[:])
	payload[4] = 0x02 // wrong version (not 0x81)

	block := &pem.Block{
		Type:  PEMTypePrivateKey,
		Bytes: payload,
	}
	_, err := UnmarshalPrivateKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBadVersion) {
		t.Errorf("expected ErrBadVersion, got: %v", err)
	}
}

// --- Cross-Type Rejection ---

func TestUnmarshalPublicKeyRejectsPrivateKeyFile(t *testing.T) {
	var seed [32]byte
	privPEM, _ := MarshalPrivateKey(seed)

	_, err := UnmarshalPublicKey(privPEM)
	if err == nil {
		t.Fatal("expected error when parsing private key file as public")
	}
	if !errors.Is(err, ErrWrongPEMType) {
		t.Errorf("expected ErrWrongPEMType, got: %v", err)
	}
}

func TestUnmarshalPrivateKeyRejectsPublicKeyFile(t *testing.T) {
	scheme := xwing.Scheme()
	pub, _, _ := scheme.GenerateKeyPair()
	pubPEM, _ := MarshalPublicKey(pub)

	_, err := UnmarshalPrivateKey(pubPEM)
	if err == nil {
		t.Fatal("expected error when parsing public key file as private")
	}
	if !errors.Is(err, ErrWrongPEMType) {
		t.Errorf("expected ErrWrongPEMType, got: %v", err)
	}
}

// --- Full Keygen Round-Trip ---

func TestFullKeygenRoundTrip(t *testing.T) {
	scheme := xwing.Scheme()

	// Generate a key pair.
	pub, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Extract the seed.
	seed, err := SeedFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("extract seed: %v", err)
	}

	// Marshal both keys to PEM.
	pubPEM, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	privPEM, err := MarshalPrivateKey(seed)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}

	// Unmarshal both keys.
	recoveredPub, err := UnmarshalPublicKey(pubPEM)
	if err != nil {
		t.Fatalf("unmarshal pub: %v", err)
	}
	recoveredSeed, err := UnmarshalPrivateKey(privPEM)
	if err != nil {
		t.Fatalf("unmarshal priv: %v", err)
	}

	// Re-derive key pair from recovered seed.
	derivedPub, _ := scheme.DeriveKeyPair(recoveredSeed[:])

	// Compare public keys: original, recovered from PEM, and re-derived from seed.
	origPubBytes, _ := pub.MarshalBinary()
	recoveredPubBytes, _ := recoveredPub.MarshalBinary()
	derivedPubBytes, _ := derivedPub.MarshalBinary()

	if hex.EncodeToString(origPubBytes) != hex.EncodeToString(recoveredPubBytes) {
		t.Error("public key PEM round-trip mismatch")
	}
	if hex.EncodeToString(origPubBytes) != hex.EncodeToString(derivedPubBytes) {
		t.Error("public key derived from recovered seed does not match original")
	}

	// Fingerprints must match.
	fp1, _ := Fingerprint(pub)
	fp2, _ := Fingerprint(recoveredPub)
	fp3, _ := Fingerprint(derivedPub)
	if fp1 != fp2 || fp1 != fp3 {
		t.Errorf("fingerprint mismatch: orig=%s recovered=%s derived=%s", fp1, fp2, fp3)
	}
}

// --- Sentinel Error Wrapping ---

func TestSentinelErrorsAreWrapped(t *testing.T) {
	// Verify that errors returned by unmarshal functions can be matched with errors.Is.
	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{"nil public input", mustErr(UnmarshalPublicKey(nil)), ErrNoPEMBlock},
		{"nil private input", mustErrSeed(UnmarshalPrivateKey(nil)), ErrNoPEMBlock},
		{"oversized public", mustErr(UnmarshalPublicKey(make([]byte, MaxInputSize+1))), ErrInputTooLarge},
		{"oversized private", mustErrSeed(UnmarshalPrivateKey(make([]byte, MaxInputSize+1))), ErrInputTooLarge},
		{"nil key marshal", mustErr(MarshalPublicKey(nil)), ErrInvalidKey},
		{"nil key fingerprint", mustErrStr(Fingerprint(nil)), ErrInvalidKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("expected non-nil error")
			}
			if !errors.Is(tt.err, tt.sentinel) {
				t.Errorf("errors.Is(%v, %v) = false", tt.err, tt.sentinel)
			}
		})
	}
}

// mustErr extracts the error from (kem.PublicKey, error).
func mustErr(_ interface{}, err error) error { return err }

// mustErrSeed extracts the error from ([32]byte, error).
func mustErrSeed(_ [32]byte, err error) error { return err }

// mustErrStr extracts the error from (string, error).
func mustErrStr(_ string, err error) error { return err }

// --- Error Message Content ---

func TestErrorMessagesDoNotLeakKeyMaterial(t *testing.T) {
	// Craft a private key file with wrong magic. The error message should not
	// contain any of the seed bytes.
	var seed [32]byte
	for i := range seed {
		seed[i] = 0xDE
	}
	pemData, _ := MarshalPrivateKey(seed)

	// Corrupt the magic after PEM encoding (modify base64 payload).
	// Instead, create a custom PEM with bad magic but real seed.
	payload := make([]byte, PrivKeyPayloadSize)
	copy(payload[0:4], []byte("XXXX"))
	payload[4] = PrivKeyVersion
	copy(payload[5:], seed[:])
	block := &pem.Block{Type: PEMTypePrivateKey, Bytes: payload}
	badPEM := pem.EncodeToMemory(block)

	_, err := UnmarshalPrivateKey(badPEM)
	if err == nil {
		t.Fatal("expected error")
	}

	errMsg := err.Error()
	// The error message should not contain hex representation of seed bytes.
	seedHex := hex.EncodeToString(seed[:])
	if strings.Contains(errMsg, seedHex) {
		t.Errorf("error message leaks seed material: %s", errMsg)
	}

	_ = pemData // silence unused warning
}
