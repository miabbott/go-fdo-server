// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package db tests for state_vouchers.go
//
// This file contains unit tests for the voucher and key management functions
// in state_vouchers.go, including:
//   - Voucher CRUD operations (NewVoucher, AddVoucher, ReplaceVoucher, RemoveVoucher, Voucher)
//   - Rendezvous blob storage and retrieval (SetRVBlob, RVBlob)
//   - Owner key management (AddOwnerKey, OwnerKey)
//   - Manufacturer key management (AddManufacturerKey, ManufacturerKey)
//
// Tests use an in-memory SQLite database and test vouchers from the go-fdo testdata package.
package db

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/testdata"
)

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

// setupTestState initializes an in-memory SQLite database for testing.
// The database is automatically closed when the test completes via t.Cleanup.
// Uses a shared cache to allow multiple connections to the same in-memory database.
func setupTestState(t *testing.T) *State {
	t.Helper()
	state, err := InitDb("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = state.Close()
	})
	return state
}

// loadTestVoucher loads the standard test voucher from the go-fdo testdata package.
// The voucher is a valid FDO ownership voucher that can be used for testing
// voucher storage, retrieval, and manipulation operations.
func loadTestVoucher(t *testing.T) *fdo.Voucher {
	t.Helper()
	voucherPEM, err := testdata.Files.ReadFile("ov.pem")
	if err != nil {
		t.Fatalf("failed to read test voucher: %v", err)
	}

	block, _ := pem.Decode(voucherPEM)
	if block == nil {
		t.Fatal("failed to decode PEM from testdata")
	}

	var voucher fdo.Voucher
	if err := cbor.Unmarshal(block.Bytes, &voucher); err != nil {
		t.Fatalf("failed to unmarshal voucher: %v", err)
	}
	return &voucher
}

// generateTestCert creates a self-signed X.509 certificate for an ECDSA key.
// The certificate is valid for 24 hours and includes digital signature key usage.
// This is used to create certificate chains for owner and manufacturer key tests.
func generateTestCert(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

// generateRSATestCert creates an RSA private key and a self-signed X.509 certificate.
// The bits parameter specifies the key size (e.g., 2048, 3072).
// This is used to test RSA key types including Rsa2048RestrKeyType, RsaPkcsKeyType, and RsaPssKeyType.
func generateRSATestCert(t *testing.T, bits int) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return key, cert
}

// ---------------------------------------------------------------------------
// Voucher CRUD Tests
// ---------------------------------------------------------------------------

// TestNewVoucher verifies that a newly created voucher can be stored and retrieved.
// This tests the ManufacturerVoucherPersistentState.NewVoucher implementation.
func TestNewVoucher(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()
	voucher := loadTestVoucher(t)

	err := state.NewVoucher(ctx, voucher)
	if err != nil {
		t.Fatalf("NewVoucher failed: %v", err)
	}

	retrieved, err := state.Voucher(ctx, voucher.Header.Val.GUID)
	if err != nil {
		t.Fatalf("Voucher retrieval failed: %v", err)
	}

	if retrieved.Header.Val.GUID != voucher.Header.Val.GUID {
		t.Errorf("GUID mismatch: got %v, want %v", retrieved.Header.Val.GUID, voucher.Header.Val.GUID)
	}
	if retrieved.Header.Val.DeviceInfo != voucher.Header.Val.DeviceInfo {
		t.Errorf("DeviceInfo mismatch: got %v, want %v", retrieved.Header.Val.DeviceInfo, voucher.Header.Val.DeviceInfo)
	}
}

// TestAddVoucher verifies that a voucher can be added to the owner service.
// This tests the OwnerVoucherPersistentState.AddVoucher implementation.
func TestAddVoucher(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()
	voucher := loadTestVoucher(t)

	err := state.AddVoucher(ctx, voucher)
	if err != nil {
		t.Fatalf("AddVoucher failed: %v", err)
	}

	retrieved, err := state.Voucher(ctx, voucher.Header.Val.GUID)
	if err != nil {
		t.Fatalf("Voucher retrieval failed: %v", err)
	}

	if retrieved.Header.Val.GUID != voucher.Header.Val.GUID {
		t.Errorf("GUID mismatch: got %v, want %v", retrieved.Header.Val.GUID, voucher.Header.Val.GUID)
	}
}

// TestVoucher_NotFound verifies that retrieving a non-existent voucher returns ErrNotFound.
// This ensures proper error handling when a GUID does not exist in the database.
func TestVoucher_NotFound(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	nonExistentGUID := protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	_, err := state.Voucher(ctx, nonExistentGUID)
	if err != fdo.ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestRemoveVoucher verifies that a voucher can be removed from the database.
// After removal, the voucher should no longer be retrievable (ErrNotFound).
func TestRemoveVoucher(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()
	voucher := loadTestVoucher(t)

	err := state.AddVoucher(ctx, voucher)
	if err != nil {
		t.Fatalf("AddVoucher failed: %v", err)
	}

	removed, err := state.RemoveVoucher(ctx, voucher.Header.Val.GUID)
	if err != nil {
		t.Fatalf("RemoveVoucher failed: %v", err)
	}

	if removed.Header.Val.GUID != voucher.Header.Val.GUID {
		t.Errorf("removed voucher GUID mismatch")
	}

	_, err = state.Voucher(ctx, voucher.Header.Val.GUID)
	if err != fdo.ErrNotFound {
		t.Errorf("expected ErrNotFound after removal, got: %v", err)
	}
}

// TestRemoveVoucher_NotFound verifies that removing a non-existent voucher returns ErrNotFound.
func TestRemoveVoucher_NotFound(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	nonExistentGUID := protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	_, err := state.RemoveVoucher(ctx, nonExistentGUID)
	if err != fdo.ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestReplaceVoucher verifies the voucher replacement flow during TO2 completion.
// When a device completes onboarding, its voucher is replaced with a new one containing
// a new GUID. This test verifies that:
//   - The old voucher is deleted
//   - The new voucher is stored with the new GUID
//   - A DeviceOnboarding record is created with TO2Completed=true and timestamp
func TestReplaceVoucher(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()
	voucher := loadTestVoucher(t)

	err := state.AddVoucher(ctx, voucher)
	if err != nil {
		t.Fatalf("AddVoucher failed: %v", err)
	}

	oldGUID := voucher.Header.Val.GUID

	newGUID := protocol.GUID{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	voucher.Header.Val.GUID = newGUID

	err = state.ReplaceVoucher(ctx, oldGUID, voucher)
	if err != nil {
		t.Fatalf("ReplaceVoucher failed: %v", err)
	}

	_, err = state.Voucher(ctx, oldGUID)
	if err != fdo.ErrNotFound {
		t.Errorf("expected old voucher to be removed, got: %v", err)
	}

	retrieved, err := state.Voucher(ctx, newGUID)
	if err != nil {
		t.Fatalf("failed to retrieve new voucher: %v", err)
	}

	if retrieved.Header.Val.GUID != newGUID {
		t.Errorf("new voucher GUID mismatch")
	}

	var onboarding DeviceOnboarding
	err = state.DB.Where("guid = ?", oldGUID[:]).First(&onboarding).Error
	if err != nil {
		t.Fatalf("failed to find DeviceOnboarding record: %v", err)
	}

	if !onboarding.TO2Completed {
		t.Error("expected TO2Completed to be true")
	}
	if onboarding.TO2CompletedAt == nil {
		t.Error("expected TO2CompletedAt to be set")
	}
}

// ---------------------------------------------------------------------------
// Rendezvous Blob Tests
// ---------------------------------------------------------------------------

// TestSetRVBlob_And_RVBlob verifies that a rendezvous blob can be stored and retrieved.
// The RV blob contains the TO1d structure (owner addressing info) and the associated voucher.
// This is used during TO0/TO1 to register and look up device rendezvous information.
func TestSetRVBlob_And_RVBlob(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()
	voucher := loadTestVoucher(t)

	to1d := &cose.Sign1[protocol.To1d, []byte]{
		Payload: cbor.NewByteWrap(protocol.To1d{
			RV: []protocol.RvTO2Addr{
				{
					DNSAddress:        new(string),
					Port:              8080,
					TransportProtocol: protocol.HTTPTransport,
				},
			},
			To0dHash: protocol.Hash{},
		}),
	}
	*to1d.Payload.Val.RV[0].DNSAddress = "localhost"

	exp := time.Now().Add(time.Hour)

	err := state.SetRVBlob(ctx, voucher, to1d, exp)
	if err != nil {
		t.Fatalf("SetRVBlob failed: %v", err)
	}

	retrievedTo1d, retrievedVoucher, err := state.RVBlob(ctx, voucher.Header.Val.GUID)
	if err != nil {
		t.Fatalf("RVBlob failed: %v", err)
	}

	if retrievedVoucher.Header.Val.GUID != voucher.Header.Val.GUID {
		t.Error("voucher GUID mismatch")
	}

	if *retrievedTo1d.Payload.Val.RV[0].DNSAddress != "localhost" {
		t.Error("to1d DNS address mismatch")
	}
}

// TestRVBlob_NotFound verifies that retrieving an RV blob for a non-existent GUID returns ErrNotFound.
func TestRVBlob_NotFound(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	nonExistentGUID := protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	_, _, err := state.RVBlob(ctx, nonExistentGUID)
	if err != fdo.ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestRVBlob_Expired verifies that an expired RV blob returns ErrNotFound.
// RV blobs have an expiration time, and retrieving an expired blob should
// behave the same as if the blob does not exist. This prevents stale
// rendezvous information from being used.
func TestRVBlob_Expired(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()
	voucher := loadTestVoucher(t)

	// Create a TO1d structure with owner addressing information
	to1d := &cose.Sign1[protocol.To1d, []byte]{
		Payload: cbor.NewByteWrap(protocol.To1d{
			RV: []protocol.RvTO2Addr{
				{
					DNSAddress:        new(string),
					Port:              8080,
					TransportProtocol: protocol.HTTPTransport,
				},
			},
			To0dHash: protocol.Hash{},
		}),
	}
	*to1d.Payload.Val.RV[0].DNSAddress = "localhost"

	exp := time.Now().Add(-time.Hour)

	err := state.SetRVBlob(ctx, voucher, to1d, exp)
	if err != nil {
		t.Fatalf("SetRVBlob failed: %v", err)
	}

	_, _, err = state.RVBlob(ctx, voucher.Header.Val.GUID)
	if err != fdo.ErrNotFound {
		t.Errorf("expected ErrNotFound for expired blob, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Owner Key Tests
// ---------------------------------------------------------------------------

// TestAddOwnerKey_And_OwnerKey_ECDSA verifies storing and retrieving an ECDSA P-384 owner key.
// Owner keys are used to sign voucher extensions and prove ownership during TO2.
func TestAddOwnerKey_And_OwnerKey_ECDSA(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cert := generateTestCert(t, key)

	err = state.AddOwnerKey(protocol.Secp384r1KeyType, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("AddOwnerKey failed: %v", err)
	}

	signer, chain, err := state.OwnerKey(ctx, protocol.Secp384r1KeyType, 0)
	if err != nil {
		t.Fatalf("OwnerKey failed: %v", err)
	}

	if signer == nil {
		t.Error("expected signer to be non-nil")
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 certificate in chain, got %d", len(chain))
	}
}

// TestAddOwnerKey_And_OwnerKey_RSA2048 verifies storing and retrieving an RSA 2048-bit owner key.
// The Rsa2048RestrKeyType is the restricted RSA key type defined in the FDO specification.
func TestAddOwnerKey_And_OwnerKey_RSA2048(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	key, cert := generateRSATestCert(t, 2048)

	err := state.AddOwnerKey(protocol.Rsa2048RestrKeyType, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("AddOwnerKey failed: %v", err)
	}

	signer, chain, err := state.OwnerKey(ctx, protocol.Rsa2048RestrKeyType, 2048)
	if err != nil {
		t.Fatalf("OwnerKey failed: %v", err)
	}

	if signer == nil {
		t.Error("expected signer to be non-nil")
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 certificate in chain, got %d", len(chain))
	}

	rsaKey, ok := signer.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("expected RSA private key")
	}
	if rsaKey.Size()*8 != 2048 {
		t.Errorf("expected 2048-bit key, got %d", rsaKey.Size()*8)
	}
}

// TestAddOwnerKey_And_OwnerKey_RSA_PKCS verifies storing and retrieving an RSA PKCS#1 v1.5 key.
// This tests the RsaPkcsKeyType with a 3072-bit key, demonstrating support for
// variable RSA key sizes beyond the restricted 2048-bit type.
func TestAddOwnerKey_And_OwnerKey_RSA_PKCS(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	key, cert := generateRSATestCert(t, 3072)

	err := state.AddOwnerKey(protocol.RsaPkcsKeyType, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("AddOwnerKey failed: %v", err)
	}

	signer, chain, err := state.OwnerKey(ctx, protocol.RsaPkcsKeyType, 3072)
	if err != nil {
		t.Fatalf("OwnerKey failed: %v", err)
	}

	if signer == nil {
		t.Error("expected signer to be non-nil")
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 certificate in chain, got %d", len(chain))
	}
}

// TestOwnerKey_NotFound verifies that requesting a non-existent key type returns ErrNotFound.
func TestOwnerKey_NotFound(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	_, _, err := state.OwnerKey(ctx, protocol.Secp256r1KeyType, 0)
	if err != fdo.ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Manufacturer Key Tests
// ---------------------------------------------------------------------------

// TestAddManufacturerKey_And_ManufacturerKey_ECDSA verifies storing and retrieving
// an ECDSA P-256 manufacturer key. Manufacturer keys are used during device
// initialization (DI) to sign the initial voucher.
func TestAddManufacturerKey_And_ManufacturerKey_ECDSA(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cert := generateTestCert(t, key)

	err = state.AddManufacturerKey(protocol.Secp256r1KeyType, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("AddManufacturerKey failed: %v", err)
	}

	signer, chain, err := state.ManufacturerKey(ctx, protocol.Secp256r1KeyType, 0)
	if err != nil {
		t.Fatalf("ManufacturerKey failed: %v", err)
	}

	if signer == nil {
		t.Error("expected signer to be non-nil")
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 certificate in chain, got %d", len(chain))
	}
}

// TestAddManufacturerKey_And_ManufacturerKey_RSA2048 verifies storing and retrieving
// an RSA 2048-bit manufacturer key with the restricted key type.
func TestAddManufacturerKey_And_ManufacturerKey_RSA2048(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	key, cert := generateRSATestCert(t, 2048)

	err := state.AddManufacturerKey(protocol.Rsa2048RestrKeyType, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("AddManufacturerKey failed: %v", err)
	}

	signer, chain, err := state.ManufacturerKey(ctx, protocol.Rsa2048RestrKeyType, 2048)
	if err != nil {
		t.Fatalf("ManufacturerKey failed: %v", err)
	}

	if signer == nil {
		t.Error("expected signer to be non-nil")
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 certificate in chain, got %d", len(chain))
	}
}

// TestAddManufacturerKey_And_ManufacturerKey_RSA_PSS verifies storing and retrieving
// an RSA-PSS manufacturer key. RSA-PSS uses probabilistic signature scheme padding
// and is considered more secure than PKCS#1 v1.5 signatures.
func TestAddManufacturerKey_And_ManufacturerKey_RSA_PSS(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	key, cert := generateRSATestCert(t, 3072)

	err := state.AddManufacturerKey(protocol.RsaPssKeyType, key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("AddManufacturerKey failed: %v", err)
	}

	signer, chain, err := state.ManufacturerKey(ctx, protocol.RsaPssKeyType, 3072)
	if err != nil {
		t.Fatalf("ManufacturerKey failed: %v", err)
	}

	if signer == nil {
		t.Error("expected signer to be non-nil")
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 certificate in chain, got %d", len(chain))
	}
}

// TestManufacturerKey_NotFound verifies that requesting a non-existent manufacturer
// key type returns ErrNotFound.
func TestManufacturerKey_NotFound(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	_, _, err := state.ManufacturerKey(ctx, protocol.Secp384r1KeyType, 0)
	if err != fdo.ErrNotFound {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Certificate Chain Tests
// ---------------------------------------------------------------------------

// TestOwnerKey_MultipleCertificates verifies that a certificate chain with multiple
// certificates can be stored and retrieved correctly. FDO supports certificate chains
// for key validation, and this test ensures the entire chain is preserved.
func TestOwnerKey_MultipleCertificates(t *testing.T) {
	state := setupTestState(t)
	ctx := context.Background()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cert1 := generateTestCert(t, key)
	cert2 := generateTestCert(t, key)

	err = state.AddOwnerKey(protocol.Secp384r1KeyType, key, []*x509.Certificate{cert1, cert2})
	if err != nil {
		t.Fatalf("AddOwnerKey failed: %v", err)
	}

	_, chain, err := state.OwnerKey(ctx, protocol.Secp384r1KeyType, 0)
	if err != nil {
		t.Fatalf("OwnerKey failed: %v", err)
	}

	if len(chain) != 2 {
		t.Errorf("expected 2 certificates in chain, got %d", len(chain))
	}
}

// ---------------------------------------------------------------------------
// Error Case Tests
// ---------------------------------------------------------------------------

// TestAddOwnerKey_NonRSAKeyWithRSAType verifies that adding an ECDSA key with an
// RSA key type returns an error. The key type must match the actual key algorithm
// to ensure proper signature verification during FDO protocol operations.
func TestAddOwnerKey_NonRSAKeyWithRSAType(t *testing.T) {
	state := setupTestState(t)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cert := generateTestCert(t, key)

	err = state.AddOwnerKey(protocol.RsaPkcsKeyType, key, []*x509.Certificate{cert})
	if err == nil {
		t.Error("expected error when adding ECDSA key with RSA key type")
	}
}

// TestAddManufacturerKey_NonRSAKeyWithRSAType verifies that adding an ECDSA key
// with an RSA key type returns an error. This is the manufacturer key equivalent
// of TestAddOwnerKey_NonRSAKeyWithRSAType.
func TestAddManufacturerKey_NonRSAKeyWithRSAType(t *testing.T) {
	state := setupTestState(t)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cert := generateTestCert(t, key)

	err = state.AddManufacturerKey(protocol.RsaPssKeyType, key, []*x509.Certificate{cert})
	if err == nil {
		t.Error("expected error when adding ECDSA key with RSA key type")
	}
}
