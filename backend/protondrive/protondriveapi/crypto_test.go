package protondriveapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// ---- helpers ---------------------------------------------------------------

func generateTestKeyRing(t *testing.T, name, email string) *pgpcrypto.KeyRing {
	t.Helper()
	passphrase := "test-passphrase"
	armored, err := helper.GenerateKey(name, email, []byte(passphrase), "x25519", 0)
	if err != nil {
		t.Fatalf("generateTestKeyRing: GenerateKey: %v", err)
	}
	lockedKey, err := pgpcrypto.NewKeyFromArmored(armored)
	if err != nil {
		t.Fatalf("generateTestKeyRing: NewKeyFromArmored: %v", err)
	}
	unlockedKey, err := lockedKey.Unlock([]byte(passphrase))
	if err != nil {
		t.Fatalf("generateTestKeyRing: Unlock: %v", err)
	}
	kr, err := pgpcrypto.NewKeyRing(unlockedKey)
	if err != nil {
		t.Fatalf("generateTestKeyRing: NewKeyRing: %v", err)
	}
	return kr
}

// ---- Tests: generateNodePassphrase -----------------------------------------

func TestGenerateNodePassphrase(t *testing.T) {
	p1, err := generateNodePassphrase()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p2, err := generateNodePassphrase()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1 == "" {
		t.Error("passphrase should not be empty")
	}
	if p1 == p2 {
		t.Error("two generated passphrases should differ")
	}
}

// ---- Tests: generateArmoredKey ---------------------------------------------

func TestGenerateArmoredKey(t *testing.T) {
	passphrase := "pass"
	armored, err := generateArmoredKey(passphrase)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(armored, "-----BEGIN PGP PRIVATE KEY BLOCK-----") {
		t.Error("expected armored PGP private key block")
	}
	key, err := pgpcrypto.NewKeyFromArmored(armored)
	if err != nil {
		t.Fatalf("NewKeyFromArmored: %v", err)
	}
	_, err = key.Unlock([]byte(passphrase))
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

// ---- Tests: GenerateNodeKeys / UnlockNodeKey --------------------------------

func TestGenerateNodeKeysAndUnlock(t *testing.T) {
	parentKR := generateTestKeyRing(t, "parent", "parent@test")
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	nodeKeyArmored, passEnc, passSig, err := GenerateNodeKeys(parentKR, addrKR)
	if err != nil {
		t.Fatalf("GenerateNodeKeys: %v", err)
	}
	if nodeKeyArmored == "" || passEnc == "" || passSig == "" {
		t.Error("all three outputs should be non-empty")
	}

	kr, err := UnlockNodeKey(nodeKeyArmored, passEnc, passSig, parentKR, addrKR)
	if err != nil {
		t.Fatalf("UnlockNodeKey: %v", err)
	}
	if kr.CountDecryptionEntities() == 0 {
		t.Error("unlocked keyring should have decryption entities")
	}
}

// ---- Tests: name encryption / decryption -----------------------------------

func TestEncryptDecryptName(t *testing.T) {
	parentKR := generateTestKeyRing(t, "parent", "parent@test")
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	name := "my-secret-file.txt"
	enc, err := EncryptName(name, parentKR, addrKR)
	if err != nil {
		t.Fatalf("EncryptName: %v", err)
	}
	if !strings.Contains(enc, "-----BEGIN PGP MESSAGE-----") {
		t.Error("expected armored PGP message")
	}

	dec, err := DecryptName(enc, parentKR, addrKR)
	if err != nil {
		t.Fatalf("DecryptName: %v", err)
	}
	if dec != name {
		t.Errorf("expected %q got %q", name, dec)
	}
}

func TestEncryptNameDifferentEachTime(t *testing.T) {
	parentKR := generateTestKeyRing(t, "parent", "parent@test")
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	name := "file.txt"
	enc1, err := EncryptName(name, parentKR, addrKR)
	if err != nil {
		t.Fatalf("EncryptName 1: %v", err)
	}
	enc2, err := EncryptName(name, parentKR, addrKR)
	if err != nil {
		t.Fatalf("EncryptName 2: %v", err)
	}
	if enc1 == enc2 {
		t.Error("two encryptions of the same name should produce different ciphertexts")
	}
}

// ---- Tests: ComputeNameHash ------------------------------------------------

func TestComputeNameHash(t *testing.T) {
	hashKey := []byte("test-hash-key-32-bytes-long!!!!!")
	name := "hello.txt"

	got, err := ComputeNameHash(name, hashKey)
	if err != nil {
		t.Fatalf("ComputeNameHash: %v", err)
	}

	mac := hmac.New(sha256.New, hashKey)
	mac.Write([]byte(name))
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Errorf("expected %q got %q", want, got)
	}
}

func TestComputeNameHashDifferentKeys(t *testing.T) {
	key1 := []byte("key1-32-bytes-padding-xxxxxxxxxxxx")
	key2 := []byte("key2-32-bytes-padding-xxxxxxxxxxxx")
	name := "same-name.txt"

	h1, _ := ComputeNameHash(name, key1)
	h2, _ := ComputeNameHash(name, key2)
	if h1 == h2 {
		t.Error("different keys should produce different hashes")
	}
}

// ---- Tests: content key packet ---------------------------------------------

func TestGenerateAndDecryptContentKeyPacket(t *testing.T) {
	nodeKR := generateTestKeyRing(t, "node", "node@test")
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	sessionKey, encKeyPacket, sig, err := GenerateContentKeyPacket(nodeKR, addrKR)
	if err != nil {
		t.Fatalf("GenerateContentKeyPacket: %v", err)
	}
	if sessionKey == nil {
		t.Fatal("sessionKey should not be nil")
	}
	if encKeyPacket == "" || sig == "" {
		t.Error("encKeyPacket and sig should not be empty")
	}

	sessionKey2, err := DecryptContentKeyPacket(encKeyPacket, nodeKR)
	if err != nil {
		t.Fatalf("DecryptContentKeyPacket: %v", err)
	}
	if !bytes.Equal(sessionKey.Key, sessionKey2.Key) {
		t.Error("decrypted session key should match original")
	}
}

// ---- Tests: block encrypt / decrypt ----------------------------------------

func TestEncryptDecryptBlock(t *testing.T) {
	nodeKR := generateTestKeyRing(t, "node", "node@test")
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	sessionKey, _, _, err := GenerateContentKeyPacket(nodeKR, addrKR)
	if err != nil {
		t.Fatalf("GenerateContentKeyPacket: %v", err)
	}

	plaintext := []byte("hello, this is a test block of data for proton drive encryption")

	encData, encSig, sha256hash, err := EncryptBlock(plaintext, sessionKey, addrKR, nodeKR)
	if err != nil {
		t.Fatalf("EncryptBlock: %v", err)
	}
	if len(encData) == 0 {
		t.Error("encrypted data should not be empty")
	}
	if encSig == "" {
		t.Error("encrypted signature should not be empty")
	}
	if sha256hash == "" {
		t.Error("hash should not be empty")
	}
	if len(sha256hash) != 44 {
		t.Errorf("unexpected sha256 hash length: %d", len(sha256hash))
	}

	decrypted, err := DecryptBlock(encData, sessionKey, addrKR, nodeKR, encSig)
	if err != nil {
		t.Fatalf("DecryptBlock: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted data mismatch: got %q want %q", decrypted, plaintext)
	}
}

func TestDecryptBlockWrongKey(t *testing.T) {
	nodeKR := generateTestKeyRing(t, "node", "node@test")
	wrongNodeKR := generateTestKeyRing(t, "wrong", "wrong@test")
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	sessionKey, _, _, err := GenerateContentKeyPacket(nodeKR, addrKR)
	if err != nil {
		t.Fatalf("GenerateContentKeyPacket: %v", err)
	}

	plaintext := []byte("secret data")
	encData, encSig, _, err := EncryptBlock(plaintext, sessionKey, addrKR, nodeKR)
	if err != nil {
		t.Fatalf("EncryptBlock: %v", err)
	}

	// DecryptBlock uses fallback behaviour: signature verification failure
	// is non-fatal, so data is returned even with the wrong nodeKR.
	got, err := DecryptBlock(encData, sessionKey, addrKR, wrongNodeKR, encSig)
	if err != nil {
		t.Fatalf("DecryptBlock should succeed with fallback behaviour, got: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

// ---- Tests: XAttr encrypt / decrypt ----------------------------------------

func TestEncryptDecryptXAttr(t *testing.T) {
	nodeKR := generateTestKeyRing(t, "node", "node@test")
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	modTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	attrs := &RevisionXAttrCommon{
		ModificationTime: modTime.Format("2006-01-02T15:04:05-0700"),
		Size:             42000,
		BlockSizes:       []int64{4194304, 1234},
		Digests:          map[string]string{"SHA1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	}

	enc, err := EncryptXAttr(attrs, nodeKR, addrKR)
	if err != nil {
		t.Fatalf("EncryptXAttr: %v", err)
	}
	if !strings.Contains(enc, "-----BEGIN PGP MESSAGE-----") {
		t.Error("expected armored PGP message for XAttr")
	}

	dec, err := DecryptXAttr(enc, nodeKR, addrKR)
	if err != nil {
		t.Fatalf("DecryptXAttr: %v", err)
	}
	if dec.Size != attrs.Size {
		t.Errorf("Size: got %d want %d", dec.Size, attrs.Size)
	}
	if dec.ModificationTime != attrs.ModificationTime {
		t.Errorf("ModificationTime: got %q want %q", dec.ModificationTime, attrs.ModificationTime)
	}
	if len(dec.BlockSizes) != len(attrs.BlockSizes) {
		t.Errorf("BlockSizes length: got %d want %d", len(dec.BlockSizes), len(attrs.BlockSizes))
	}
	if dec.Digests["SHA1"] != attrs.Digests["SHA1"] {
		t.Errorf("SHA1: got %q want %q", dec.Digests["SHA1"], attrs.Digests["SHA1"])
	}
}

// ---- Tests: manifest signing -----------------------------------------------

func TestSignAndVerifyManifest(t *testing.T) {
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	manifestData := []byte{0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef}
	sig, err := SignManifest(manifestData, addrKR)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if !strings.Contains(sig, "-----BEGIN PGP SIGNATURE-----") {
		t.Error("expected armored PGP signature")
	}

	pgpSig, err := pgpcrypto.NewPGPSignatureFromArmored(sig)
	if err != nil {
		t.Fatalf("NewPGPSignatureFromArmored: %v", err)
	}
	err = addrKR.VerifyDetached(pgpcrypto.NewPlainMessage(manifestData), pgpSig, pgpcrypto.GetUnixTime())
	if err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
}

// ---- Tests: DecryptHashKey -------------------------------------------------

func TestEncryptDecryptHashKey(t *testing.T) {
	nodeKR := generateTestKeyRing(t, "node", "node@test")
	addrKR := generateTestKeyRing(t, "addr", "addr@test")

	rawKey := make([]byte, 32)
	copy(rawKey, []byte("deterministic-test-hash-key-xxxxx"))

	enc, err := EncryptHashKey(rawKey, nodeKR, addrKR)
	if err != nil {
		t.Fatalf("EncryptHashKey: %v", err)
	}

	dec, err := DecryptHashKey(enc, nodeKR, addrKR)
	if err != nil {
		t.Fatalf("DecryptHashKey: %v", err)
	}
	if !bytes.Equal(dec, rawKey) {
		t.Errorf("decrypted hash key mismatch: got %x want %x", dec, rawKey)
	}
}
