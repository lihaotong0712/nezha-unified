package credential

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/nezhahq/nezha/internal/resource"
)

var (
	ErrInvalidEnvelope = errors.New("invalid encrypted credential envelope")
	ErrUnknownKey      = errors.New("credential encryption key is unavailable")
	ErrSecretRequired  = errors.New("credential secret is required")
	ErrKeyExists       = errors.New("credential encryption key ID already exists")
)

// AESGCMProtector encrypts credential values with a server-managed key. The
// key itself is deliberately kept outside the credential database. Keys can be
// added during rotation while old keys remain available for reads.
type AESGCMProtector struct {
	mu      sync.RWMutex
	keys    map[string]cipher.AEAD
	current string
}

func NewAESGCMProtector(keyID string, key []byte) (*AESGCMProtector, error) {
	if keyID == "" {
		return nil, errors.New("credential encryption key ID is required")
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, fmt.Errorf("create credential encryption key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create credential encryption cipher: %w", err)
	}
	return &AESGCMProtector{keys: map[string]cipher.AEAD{keyID: aead}, current: keyID}, nil
}

// AddKey makes a key available for decryption. SetCurrentKey switches the key
// used for new values without requiring a database rewrite.
func (p *AESGCMProtector) AddKey(keyID string, key []byte) error {
	if p == nil || keyID == "" {
		return errors.New("credential encryption key ID is required")
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return fmt.Errorf("create credential encryption key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create credential encryption cipher: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys[keyID] != nil {
		return ErrKeyExists
	}
	p.keys[keyID] = aead
	return nil
}

func (p *AESGCMProtector) SetCurrentKey(keyID string) error {
	if p == nil {
		return ErrUnknownKey
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys[keyID] == nil {
		return ErrUnknownKey
	}
	p.current = keyID
	return nil
}

func (p *AESGCMProtector) Seal(ctx context.Context, credential resource.Ref, version uint64, secret *Secret) (EncryptedSecret, error) {
	if err := contextErr(ctx); err != nil {
		return EncryptedSecret{}, err
	}
	if p == nil || credential.Kind != resource.Credential || credential.Validate() != nil || version == 0 || secret == nil {
		return EncryptedSecret{}, ErrSecretRequired
	}
	p.mu.RLock()
	keyID, aead := p.current, p.keys[p.current]
	p.mu.RUnlock()
	if aead == nil {
		return EncryptedSecret{}, ErrUnknownKey
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedSecret{}, fmt.Errorf("generate credential nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, secret.Bytes(), associatedData(credential, version))
	return EncryptedSecret{KeyID: keyID, Algorithm: "AES-GCM", Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (p *AESGCMProtector) Open(ctx context.Context, credential resource.Ref, version uint64, encrypted EncryptedSecret) (*Secret, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if p == nil || credential.Kind != resource.Credential || credential.Validate() != nil || version == 0 || encrypted.KeyID == "" || encrypted.Algorithm != "AES-GCM" {
		return nil, ErrInvalidEnvelope
	}
	p.mu.RLock()
	aead := p.keys[encrypted.KeyID]
	p.mu.RUnlock()
	if aead == nil {
		return nil, ErrUnknownKey
	}
	if len(encrypted.Nonce) != aead.NonceSize() || len(encrypted.Ciphertext) < aead.Overhead() {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, encrypted.Nonce, encrypted.Ciphertext, associatedData(credential, version))
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer clear(plaintext)
	return NewSecret(plaintext), nil
}

func associatedData(credential resource.Ref, version uint64) []byte {
	// A hash gives the AEAD a fixed-size context while retaining domain
	// separation and preserving the exact resource ID and version.
	h := sha256.New()
	_, _ = h.Write([]byte("nezha-unified/credential/v1"))
	_ = binary.Write(h, binary.BigEndian, uint16(len(credential.ID)))
	_, _ = h.Write([]byte(credential.ID))
	_ = binary.Write(h, binary.BigEndian, version)
	return h.Sum(nil)
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
