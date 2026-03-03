package protondriveapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// ---- Key generation --------------------------------------------------------

// generateNodePassphrase generates a random 32-byte passphrase encoded as
// base64, suitable for use as a PGP key passphrase.
func generateNodePassphrase() (string, error) {
	token, err := pgpcrypto.RandomToken(32)
	if err != nil {
		return "", fmt.Errorf("generateNodePassphrase: %w", err)
	}
	return base64.StdEncoding.EncodeToString(token), nil
}

// generateArmoredKey generates a new x25519 PGP private key locked with the
// given passphrase and returns it as an armored string.
func generateArmoredKey(passphrase string) (string, error) {
	armored, err := helper.GenerateKey("Drive key", "noreply@protonmail.com", []byte(passphrase), "x25519", 0)
	if err != nil {
		return "", fmt.Errorf("generateArmoredKey: %w", err)
	}
	return armored, nil
}

// GenerateNodeKeys creates a new node key pair for a node, encrypting the
// passphrase to the parent's keyring and signing with the address keyring.
//
// Returns: armoredNodeKey, encryptedPassphrase, passphraseSignature.
func GenerateNodeKeys(parentKR, addrKR *pgpcrypto.KeyRing) (nodeKeyArmored, passphraseEnc, passphraseSignature string, err error) {
	passphrase, err := generateNodePassphrase()
	if err != nil {
		return "", "", "", err
	}

	nodeKeyArmored, err = generateArmoredKey(passphrase)
	if err != nil {
		return "", "", "", err
	}

	passphraseMsg := pgpcrypto.NewPlainMessageFromString(passphrase)
	encMsg, err := parentKR.Encrypt(passphraseMsg, addrKR)
	if err != nil {
		return "", "", "", fmt.Errorf("generateNodeKeys: encrypt passphrase: %w", err)
	}
	passphraseEnc, err = encMsg.GetArmored()
	if err != nil {
		return "", "", "", fmt.Errorf("generateNodeKeys: armor passphrase: %w", err)
	}

	sig, err := addrKR.SignDetached(passphraseMsg)
	if err != nil {
		return "", "", "", fmt.Errorf("generateNodeKeys: sign passphrase: %w", err)
	}
	passphraseSignature, err = sig.GetArmored()
	if err != nil {
		return "", "", "", fmt.Errorf("generateNodeKeys: armor passphrase signature: %w", err)
	}

	return nodeKeyArmored, passphraseEnc, passphraseSignature, nil
}

// decryptWithFallback tries to decrypt msg with decKR using embedded-signature
// verification against sigKR. If that fails it retries without signature
// verification. The caller label is used only in the error message.
func decryptWithFallback(msg *pgpcrypto.PGPMessage, decKR, sigKR *pgpcrypto.KeyRing, caller string) (*pgpcrypto.PlainMessage, error) {
	plain, err := decKR.Decrypt(msg, sigKR, pgpcrypto.GetUnixTime())
	if err != nil {
		plain, err = decKR.Decrypt(msg, nil, pgpcrypto.GetUnixTime())
		if err != nil {
			return nil, fmt.Errorf("%s: decrypt: %w", caller, err)
		}
	}
	return plain, nil
}

// ErrPassphraseSignatureMismatch is returned (wrapped) by UnlockNodeKey when
// the node passphrase signature fails to verify against the address keyring.
// The node key is still unlocked and returned; callers should log this as a
// warning but may continue.
var ErrPassphraseSignatureMismatch = fmt.Errorf("node passphrase signature verification failed")

// UnlockNodeKey decrypts the node key passphrase using the parent keyring,
// verifies the signature with the address keyring, and returns an unlocked
// KeyRing for the node.
//
// If the passphrase signature fails to verify, the node key is still returned
// together with an error wrapping ErrPassphraseSignatureMismatch. Callers
// should check for this sentinel and log it rather than treating it as fatal.
func UnlockNodeKey(nodeKeyArmored, passphraseEnc, passphraseSignature string, parentKR, addrKR *pgpcrypto.KeyRing) (*pgpcrypto.KeyRing, error) {
	encMsg, err := pgpcrypto.NewPGPMessageFromArmored(passphraseEnc)
	if err != nil {
		return nil, fmt.Errorf("unlockNodeKey: parse passphrase message: %w", err)
	}

	decMsg, err := decryptWithFallback(encMsg, parentKR, addrKR, "unlockNodeKey")
	if err != nil {
		return nil, err
	}

	var sigErr error
	if passphraseSignature != "" {
		sig, err := pgpcrypto.NewPGPSignatureFromArmored(passphraseSignature)
		if err != nil {
			return nil, fmt.Errorf("unlockNodeKey: parse passphrase signature: %w", err)
		}
		if err := addrKR.VerifyDetached(decMsg, sig, pgpcrypto.GetUnixTime()); err != nil {
			sigErr = fmt.Errorf("unlockNodeKey: %w: %w", ErrPassphraseSignatureMismatch, err)
		}
	}

	lockedKey, err := pgpcrypto.NewKeyFromArmored(nodeKeyArmored)
	if err != nil {
		return nil, fmt.Errorf("unlockNodeKey: parse node key: %w", err)
	}
	unlockedKey, err := lockedKey.Unlock(decMsg.GetBinary())
	if err != nil {
		return nil, fmt.Errorf("unlockNodeKey: unlock node key: %w", err)
	}
	kr, err := pgpcrypto.NewKeyRing(unlockedKey)
	if err != nil {
		return nil, fmt.Errorf("unlockNodeKey: new keyring: %w", err)
	}
	return kr, sigErr
}

// ---- Name encryption -------------------------------------------------------

// EncryptName encrypts a file/folder name to the parent node's keyring,
// signed with the address keyring. Returns an armored PGP message.
func EncryptName(name string, parentKR, addrKR *pgpcrypto.KeyRing) (string, error) {
	plain := pgpcrypto.NewPlainMessageFromString(name)
	enc, err := parentKR.Encrypt(plain, addrKR)
	if err != nil {
		return "", fmt.Errorf("encryptName: %w", err)
	}
	armored, err := enc.GetArmored()
	if err != nil {
		return "", fmt.Errorf("encryptName: armor: %w", err)
	}
	return armored, nil
}

// DecryptName decrypts an armored PGP name message using the parent node's
// keyring. The address keyring is used to verify the signature.
func DecryptName(encName string, parentKR, addrKR *pgpcrypto.KeyRing) (string, error) {
	encMsg, err := pgpcrypto.NewPGPMessageFromArmored(encName)
	if err != nil {
		return "", fmt.Errorf("decryptName: parse: %w", err)
	}
	decMsg, err := decryptWithFallback(encMsg, parentKR, addrKR, "decryptName")
	if err != nil {
		return "", err
	}
	return decMsg.GetString(), nil
}

// ComputeNameHash computes HMAC-SHA256 of name using the folder's hash key
// and returns it as a hex string. This is stored as Link.Hash.
func ComputeNameHash(name string, hashKey []byte) (string, error) {
	mac := hmac.New(sha256.New, hashKey)
	if _, err := mac.Write([]byte(name)); err != nil {
		return "", fmt.Errorf("computeNameHash: %w", err)
	}
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ---- Hash key encryption ---------------------------------------------------

// EncryptHashKey encrypts a raw NodeHashKey (32 random bytes) to the node's
// keyring, signed with the address keyring.
func EncryptHashKey(hashKey []byte, nodeKR, addrKR *pgpcrypto.KeyRing) (string, error) {
	plain := pgpcrypto.NewPlainMessage(hashKey)
	enc, err := nodeKR.Encrypt(plain, addrKR)
	if err != nil {
		return "", fmt.Errorf("encryptHashKey: %w", err)
	}
	armored, err := enc.GetArmored()
	if err != nil {
		return "", fmt.Errorf("encryptHashKey: armor: %w", err)
	}
	return armored, nil
}

// DecryptHashKey decrypts an armored PGP message containing a NodeHashKey
// using the node's keyring.
func DecryptHashKey(encHashKey string, nodeKR, addrKR *pgpcrypto.KeyRing) ([]byte, error) {
	encMsg, err := pgpcrypto.NewPGPMessageFromArmored(encHashKey)
	if err != nil {
		return nil, fmt.Errorf("decryptHashKey: parse: %w", err)
	}
	decMsg, err := decryptWithFallback(encMsg, nodeKR, addrKR, "decryptHashKey")
	if err != nil {
		return nil, err
	}
	return decMsg.GetBinary(), nil
}

// ---- Content key packet ----------------------------------------------------

// GenerateContentKeyPacket generates a new PGP session key, encrypts it to
// the node's keyring, and signs the raw key bytes with the address keyring.
//
// Returns: sessionKey, base64-encoded encrypted key packet, armored signature.
func GenerateContentKeyPacket(nodeKR, addrKR *pgpcrypto.KeyRing) (*pgpcrypto.SessionKey, string, string, error) {
	sessionKey, err := pgpcrypto.GenerateSessionKey()
	if err != nil {
		return nil, "", "", fmt.Errorf("generateContentKeyPacket: generate session key: %w", err)
	}

	encKeyPacket, err := nodeKR.EncryptSessionKey(sessionKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("generateContentKeyPacket: encrypt session key: %w", err)
	}
	encKeyPacketB64 := base64.StdEncoding.EncodeToString(encKeyPacket)

	sig, err := addrKR.SignDetached(pgpcrypto.NewPlainMessage(sessionKey.Key))
	if err != nil {
		return nil, "", "", fmt.Errorf("generateContentKeyPacket: sign: %w", err)
	}
	sigArmored, err := sig.GetArmored()
	if err != nil {
		return nil, "", "", fmt.Errorf("generateContentKeyPacket: armor signature: %w", err)
	}

	return sessionKey, encKeyPacketB64, sigArmored, nil
}

// DecryptContentKeyPacket decodes the base64 key packet and decrypts it using
// the node's keyring, returning the session key.
func DecryptContentKeyPacket(encKeyPacketB64 string, nodeKR *pgpcrypto.KeyRing) (*pgpcrypto.SessionKey, error) {
	encKeyPacket, err := base64.StdEncoding.DecodeString(encKeyPacketB64)
	if err != nil {
		return nil, fmt.Errorf("decryptContentKeyPacket: base64 decode: %w", err)
	}
	sessionKey, err := nodeKR.DecryptSessionKey(encKeyPacket)
	if err != nil {
		return nil, fmt.Errorf("decryptContentKeyPacket: decrypt: %w", err)
	}
	return sessionKey, nil
}

// ---- Block encryption ------------------------------------------------------

// EncryptBlock encrypts a block of plaintext data using the session key.
// It also signs the plaintext with an encrypted detached signature (signed by
// addrKR, encrypted to nodeKR per Proton's SignDetachedEncrypted pattern).
//
// Returns: encrypted data bytes, armored encrypted signature, base64 SHA-256
// of the encrypted data.
func EncryptBlock(data []byte, sessionKey *pgpcrypto.SessionKey, addrKR, nodeKR *pgpcrypto.KeyRing) ([]byte, string, string, error) {
	plain := pgpcrypto.NewPlainMessage(data)

	encData, err := sessionKey.Encrypt(plain)
	if err != nil {
		return nil, "", "", fmt.Errorf("encryptBlock: encrypt: %w", err)
	}

	encSig, err := addrKR.SignDetachedEncrypted(plain, nodeKR)
	if err != nil {
		return nil, "", "", fmt.Errorf("encryptBlock: sign encrypted: %w", err)
	}
	encSigArmored, err := encSig.GetArmored()
	if err != nil {
		return nil, "", "", fmt.Errorf("encryptBlock: armor signature: %w", err)
	}

	h := sha256.Sum256(encData)
	sha256B64 := base64.StdEncoding.EncodeToString(h[:])

	return encData, encSigArmored, sha256B64, nil
}

// DecryptBlock decrypts an encrypted block using the session key and verifies
// the encrypted detached signature. If signature verification fails, the
// decrypted data is returned anyway (fallback) since blocks uploaded by
// different address keys may fail verification with the caller's primary KR.
func DecryptBlock(encData []byte, sessionKey *pgpcrypto.SessionKey, addrKR, nodeKR *pgpcrypto.KeyRing, encSigArmored string) ([]byte, error) {
	plain, err := sessionKey.Decrypt(encData)
	if err != nil {
		return nil, fmt.Errorf("decryptBlock: decrypt: %w", err)
	}

	encSig, err := pgpcrypto.NewPGPMessageFromArmored(encSigArmored)
	if err != nil {
		// Signature unparseable — return data without verification.
		return plain.GetBinary(), nil
	}
	if err := addrKR.VerifyDetachedEncrypted(plain, encSig, nodeKR, pgpcrypto.GetUnixTime()); err != nil {
		// Signature verification failed — likely uploaded by a different
		// address key. Return data anyway (consistent with other decrypt
		// functions' fallback behaviour).
		return plain.GetBinary(), nil
	}

	return plain.GetBinary(), nil
}

// ---- Manifest signing ------------------------------------------------------

// SignManifest signs the manifest data (concatenation of block SHA-256 hashes)
// with the address keyring and returns an armored PGP signature.
func SignManifest(manifestData []byte, addrKR *pgpcrypto.KeyRing) (string, error) {
	sig, err := addrKR.SignDetached(pgpcrypto.NewPlainMessage(manifestData))
	if err != nil {
		return "", fmt.Errorf("signManifest: %w", err)
	}
	armored, err := sig.GetArmored()
	if err != nil {
		return "", fmt.Errorf("signManifest: armor: %w", err)
	}
	return armored, nil
}

// ---- XAttr encryption ------------------------------------------------------

// EncryptXAttr encrypts the revision extended attributes (modification time,
// plaintext size, block sizes, SHA1 digest) to the node's keyring, signed with
// the address keyring. Returns an armored PGP message.
func EncryptXAttr(attrs *RevisionXAttrCommon, nodeKR, addrKR *pgpcrypto.KeyRing) (string, error) {
	xattr := RevisionXAttr{Common: *attrs}
	jsonBytes, err := json.Marshal(xattr)
	if err != nil {
		return "", fmt.Errorf("encryptXAttr: marshal: %w", err)
	}
	plain := pgpcrypto.NewPlainMessage(jsonBytes)
	enc, err := nodeKR.Encrypt(plain, addrKR)
	if err != nil {
		return "", fmt.Errorf("encryptXAttr: encrypt: %w", err)
	}
	armored, err := enc.GetArmored()
	if err != nil {
		return "", fmt.Errorf("encryptXAttr: armor: %w", err)
	}
	return armored, nil
}

// DecryptXAttr decrypts an armored PGP XAttr message using the node's keyring.
func DecryptXAttr(encXAttr string, nodeKR, addrKR *pgpcrypto.KeyRing) (*RevisionXAttrCommon, error) {
	encMsg, err := pgpcrypto.NewPGPMessageFromArmored(encXAttr)
	if err != nil {
		return nil, fmt.Errorf("decryptXAttr: parse: %w", err)
	}
	decMsg, err := decryptWithFallback(encMsg, nodeKR, addrKR, "decryptXAttr")
	if err != nil {
		return nil, err
	}

	var xattr RevisionXAttr
	if err := json.Unmarshal(decMsg.GetBinary(), &xattr); err != nil {
		return nil, fmt.Errorf("decryptXAttr: unmarshal: %w", err)
	}
	return &xattr.Common, nil
}

// decryptSessionKey tries to decrypt keyPacket using each candidate KeyRing in
// order, skipping nil entries, and returns the first success. If all candidates
// fail the last error is returned. If all candidates are nil, an explicit error
// is returned to avoid a (nil, nil) result that would cause callers to panic.
func decryptSessionKey(keyPacket []byte, candidates ...*pgpcrypto.KeyRing) (*pgpcrypto.SessionKey, error) {
	var err error
	tried := false
	for _, kr := range candidates {
		if kr == nil {
			continue
		}
		tried = true
		var sk *pgpcrypto.SessionKey
		sk, err = kr.DecryptSessionKey(keyPacket)
		if err == nil {
			return sk, nil
		}
	}
	if !tried {
		return nil, fmt.Errorf("decryptSessionKey: no non-nil keyrings provided")
	}
	return nil, err
}

// ReEncryptName re-encrypts a node name for a new parent keyring while
// reusing the original name session key and optionally changing the plaintext.
func ReEncryptName(armoredName, newName string, srcParentKR, dstParentKR, addrKR, userKR *pgpcrypto.KeyRing) (string, error) {
	split, err := pgpcrypto.NewPGPSplitMessageFromArmored(armoredName)
	if err != nil {
		return "", fmt.Errorf("reEncryptName: split: %w", err)
	}

	sk, err := decryptSessionKey(split.GetBinaryKeyPacket(), srcParentKR, addrKR, userKR)
	if err != nil {
		return "", fmt.Errorf("reEncryptName: decrypt session key: %w", err)
	}

	dataPacket, err := sk.EncryptAndSign(pgpcrypto.NewPlainMessageFromString(newName), addrKR)
	if err != nil {
		return "", fmt.Errorf("reEncryptName: encrypt: %w", err)
	}

	newKeyPacket, err := dstParentKR.EncryptSessionKey(sk)
	if err != nil {
		return "", fmt.Errorf("reEncryptName: encrypt session key: %w", err)
	}

	armored, err := pgpcrypto.NewPGPSplitMessage(newKeyPacket, dataPacket).GetArmored()
	if err != nil {
		return "", fmt.Errorf("reEncryptName: armor: %w", err)
	}
	return armored, nil
}

// ReEncryptPassphrase re-encrypts a node passphrase to a new parent
// keyring while reusing the original symmetric session key.
func ReEncryptPassphrase(armoredPassphrase string, srcParentKR, dstParentKR, addrKR, userKR *pgpcrypto.KeyRing) (string, error) {
	split, err := pgpcrypto.NewPGPSplitMessageFromArmored(armoredPassphrase)
	if err != nil {
		return "", fmt.Errorf("reEncryptPassphrase: split: %w", err)
	}

	sk, err := decryptSessionKey(split.GetBinaryKeyPacket(), srcParentKR, addrKR, userKR)
	if err != nil {
		return "", fmt.Errorf("reEncryptPassphrase: decrypt session key: %w", err)
	}

	newKeyPacket, err := dstParentKR.EncryptSessionKey(sk)
	if err != nil {
		return "", fmt.Errorf("reEncryptPassphrase: encrypt session key: %w", err)
	}

	armored, err := pgpcrypto.NewPGPSplitMessage(newKeyPacket, split.GetBinaryDataPacket()).GetArmored()
	if err != nil {
		return "", fmt.Errorf("reEncryptPassphrase: armor: %w", err)
	}
	return armored, nil
}
