// Package credentials provides envelope encryption and encrypted credential
// storage primitives and exposes no API that serializes plaintext.
package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const dataKeyBytes = 32

// KMS wraps and unwraps per-credential data-encryption keys. A production
// implementation should delegate these methods to Vault transit or a cloud KMS.
type KMS interface {
	KeyWrapper
	KeyUnwrapper
}

type KeyWrapper interface {
	KeyID() string
	WrapKey(ctx context.Context, dataKey, aad []byte) (wrappedKey, nonce []byte, err error)
}

type KeyUnwrapper interface {
	KeyID() string
	UnwrapKey(ctx context.Context, wrappedKey, nonce, aad []byte) ([]byte, error)
}

// Envelope contains ciphertext only. Its fields are excluded from
// JSON so an accidental API serialization cannot disclose encrypted blobs or
// wrapping metadata.
type Envelope struct {
	Ciphertext []byte `json:"-"`
	Nonce      []byte `json:"-"`
	WrappedKey []byte `json:"-"`
	KeyNonce   []byte `json:"-"`
	KeyID      string `json:"-"`
}

func (Envelope) String() string   { return "[encrypted credential]" }
func (Envelope) GoString() string { return "credentials.Envelope{[redacted]}" }

var ErrUnwrapUnavailable = errors.New("credential decryption is unavailable in this process")

type Service struct {
	wrapper   KeyWrapper
	unwrapper KeyUnwrapper
}

func NewService(kms KMS) (*Service, error) {
	if kms == nil || kms.KeyID() == "" {
		return nil, errors.New("kms with a key id is required")
	}
	return &Service{wrapper: kms, unwrapper: kms}, nil
}

// NewSealingService constructs an upload identity with no decryption path.
func NewSealingService(wrapper KeyWrapper) (*Service, error) {
	if wrapper == nil || wrapper.KeyID() == "" {
		return nil, errors.New("key wrapper with a key id is required")
	}
	return &Service{wrapper: wrapper}, nil
}

func (s *Service) Seal(ctx context.Context, plaintext, aad []byte) (Envelope, error) {
	if len(plaintext) == 0 {
		return Envelope{}, errors.New("credential plaintext is empty")
	}
	if len(aad) == 0 {
		return Envelope{}, errors.New("credential encryption context is required")
	}
	dataKey := make([]byte, dataKeyBytes)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return Envelope{}, fmt.Errorf("generate data key: %w", err)
	}
	defer wipe(dataKey)

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return Envelope{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate credential nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	wrapped, keyNonce, err := s.wrapper.WrapKey(ctx, dataKey, aad)
	if err != nil {
		return Envelope{}, fmt.Errorf("wrap data key: %w", err)
	}
	return Envelope{Ciphertext: ciphertext, Nonce: nonce, WrappedKey: wrapped, KeyNonce: keyNonce, KeyID: s.wrapper.KeyID()}, nil
}

// Open invokes use while plaintext is in memory, then best-effort wipes the
// plaintext buffer. Callers should not retain the supplied slice.
func (s *Service) Open(ctx context.Context, envelope Envelope, aad []byte, use func([]byte) error) error {
	if use == nil {
		return errors.New("credential consumer is required")
	}
	if s.unwrapper == nil {
		return ErrUnwrapUnavailable
	}
	if envelope.KeyID != s.unwrapper.KeyID() {
		return errors.New("credential key id is not available")
	}
	dataKey, err := s.unwrapper.UnwrapKey(ctx, envelope.WrappedKey, envelope.KeyNonce, aad)
	if err != nil {
		return fmt.Errorf("unwrap data key: %w", err)
	}
	defer wipe(dataKey)
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(envelope.Nonce) != gcm.NonceSize() || len(envelope.Ciphertext) < gcm.Overhead() {
		return errors.New("credential envelope is malformed")
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return errors.New("credential authentication failed")
	}
	defer wipe(plaintext)
	return use(plaintext)
}

// DevKMS is an in-memory AES-GCM key wrapper for local development.
// It is non-persistent and must not be used for durable or production
// credentials.
type DevKMS struct {
	keyID  string
	master []byte
}

func NewDevKMS(keyID string, masterKey []byte) (*DevKMS, error) {
	if keyID == "" || len(masterKey) != dataKeyBytes {
		return nil, errors.New("dev kms requires a key id and a 32-byte master key")
	}
	return &DevKMS{keyID: keyID, master: append([]byte(nil), masterKey...)}, nil
}

func NewRandomDevKMS() (*DevKMS, error) {
	master := make([]byte, dataKeyBytes)
	if _, err := io.ReadFull(rand.Reader, master); err != nil {
		return nil, err
	}
	defer wipe(master)
	return NewDevKMS("dev-ephemeral-"+time.Now().UTC().Format("20060102T150405Z"), master)
}

func (k *DevKMS) KeyID() string { return k.keyID }

func (k *DevKMS) WrapKey(_ context.Context, dataKey, aad []byte) ([]byte, []byte, error) {
	gcm, err := k.aead()
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, dataKey, aad), nonce, nil
}

func (k *DevKMS) UnwrapKey(_ context.Context, wrappedKey, nonce, aad []byte) ([]byte, error) {
	gcm, err := k.aead()
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() || len(wrappedKey) < gcm.Overhead() {
		return nil, errors.New("wrapped data key is malformed")
	}
	key, err := gcm.Open(nil, nonce, wrappedKey, aad)
	if err != nil {
		return nil, errors.New("wrapped data key authentication failed")
	}
	return key, nil
}

func (k *DevKMS) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.master)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// MarshalJSON makes accidental direct serialization explicit and harmless.
func (Envelope) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Encrypted bool `json:"encrypted"`
	}{Encrypted: true})
}
