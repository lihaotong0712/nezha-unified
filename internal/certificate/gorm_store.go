package certificate

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/gorm"
)

// ProtectedMaterialStore keeps certificate and private-key bytes outside the
// metadata row. Implementations must protect material at rest and return a
// copy that the caller owns.
type ProtectedMaterialStore interface {
	Put(context.Context, resource.Ref, []byte, []byte) error
	Get(context.Context, resource.Ref) ([]byte, []byte, error)
	Delete(context.Context, resource.Ref) error
}

type certificateRow struct {
	RefID        string    `gorm:"primaryKey;size:255"`
	OwnerID      uint64    `gorm:"not null;index"`
	Name         string    `gorm:"not null;size:255"`
	Source       string    `gorm:"not null;size:32"`
	Status       string    `gorm:"not null;size:32;index"`
	SerialNumber string    `gorm:"not null;size:255"`
	Subject      string    `gorm:"not null;type:text"`
	Issuer       string    `gorm:"not null;type:text"`
	DNSNamesJSON string    `gorm:"not null;type:text"`
	IPJSON       string    `gorm:"not null;type:text"`
	NotBefore    time.Time `gorm:"not null"`
	NotAfter     time.Time `gorm:"not null;index"`
	Revision     uint64    `gorm:"not null"`
	CreatedAt    time.Time `gorm:"not null"`
	UpdatedAt    time.Time `gorm:"not null;index"`
}

func (certificateRow) TableName() string { return "platform_certificates" }

// GORMStore persists safe certificate metadata and delegates secret material
// to a protected store. The metadata table contains no PEM or private-key
// fields, so ordinary list/detail queries cannot expose secret bytes.
type GORMStore struct {
	db        *gorm.DB
	materials ProtectedMaterialStore
}

func NewGORMStore(db *gorm.DB, materials ProtectedMaterialStore) (*GORMStore, error) {
	if db == nil || materials == nil {
		return nil, errors.New("certificate: database and protected material store are required")
	}
	if err := db.AutoMigrate(&certificateRow{}); err != nil {
		return nil, fmt.Errorf("certificate metadata migration: %w", err)
	}
	return &GORMStore{db: db, materials: materials}, nil
}

func rowFromRecord(r Record) (certificateRow, error) {
	if err := r.Validate(); err != nil {
		return certificateRow{}, err
	}
	dns, err := json.Marshal(r.DNSNames)
	if err != nil {
		return certificateRow{}, err
	}
	ips, err := json.Marshal(r.IPAddresses)
	if err != nil {
		return certificateRow{}, err
	}
	return certificateRow{
		RefID: r.Ref.ID, OwnerID: r.OwnerID, Name: r.Name, Source: string(r.Source), Status: string(r.Status),
		SerialNumber: r.SerialNumber, Subject: r.Subject, Issuer: r.Issuer,
		DNSNamesJSON: string(dns), IPJSON: string(ips), NotBefore: r.NotBefore.UTC(), NotAfter: r.NotAfter.UTC(),
		Revision: r.Revision, CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(),
	}, nil
}

func recordFromRow(row certificateRow) (Record, error) {
	var dns, ips []string
	if err := json.Unmarshal([]byte(row.DNSNamesJSON), &dns); err != nil {
		return Record{}, ErrInvalidCertificate
	}
	if err := json.Unmarshal([]byte(row.IPJSON), &ips); err != nil {
		return Record{}, ErrInvalidCertificate
	}
	record := Record{Ref: resource.Ref{Kind: resource.Certificate, ID: row.RefID}, OwnerID: row.OwnerID, Name: row.Name, Source: Source(row.Source), Status: Status(row.Status), SerialNumber: row.SerialNumber, Subject: row.Subject, Issuer: row.Issuer, DNSNames: dns, IPAddresses: ips, NotBefore: row.NotBefore.UTC(), NotAfter: row.NotAfter.UTC(), Revision: row.Revision, CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC()}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *GORMStore) Create(ctx context.Context, record Record, certificatePEM, privateKeyPEM []byte) error {
	if s == nil || s.db == nil || s.materials == nil {
		return ErrInvalidCertificate
	}
	row, err := rowFromRecord(record)
	if err != nil || len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return ErrInvalidCertificate
	}
	if err := s.materials.Put(ctx, record.Ref, certificatePEM, privateKeyPEM); err != nil {
		return err
	}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		_ = s.materials.Delete(context.WithoutCancel(ctx), record.Ref)
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (s *GORMStore) Get(ctx context.Context, ref resource.Ref) (Record, error) {
	if s == nil || s.db == nil || ref.Kind != resource.Certificate || ref.Validate() != nil {
		return Record{}, ErrNotFound
	}
	var row certificateRow
	if err := s.db.WithContext(ctx).First(&row, "ref_id = ?", ref.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	return recordFromRow(row)
}

func (s *GORMStore) List(ctx context.Context, ownerID uint64) ([]Record, error) {
	if s == nil || s.db == nil || ownerID == 0 {
		return nil, ErrInvalidCertificate
	}
	var rows []certificateRow
	if err := s.db.WithContext(ctx).Where("owner_id = ?", ownerID).Order("updated_at ASC, ref_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(rows))
	for _, row := range rows {
		record, err := recordFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (s *GORMStore) Delete(ctx context.Context, ref resource.Ref) error {
	if s == nil || s.db == nil || ref.Kind != resource.Certificate || ref.Validate() != nil {
		return ErrNotFound
	}
	var current certificateRow
	if err := s.db.WithContext(ctx).First(&current, "ref_id = ?", ref.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	certificatePEM, privateKeyPEM, err := s.materials.Get(ctx, ref)
	if err != nil {
		return err
	}
	defer clear(certificatePEM)
	defer clear(privateKeyPEM)
	if err := s.materials.Delete(ctx, ref); err != nil {
		if restoreErr := s.restoreMaterialIfMetadataPresent(ctx, ref, certificatePEM, privateKeyPEM); restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		return err
	}
	result := s.db.WithContext(ctx).Delete(&certificateRow{}, "ref_id = ?", ref.ID)
	if result.Error != nil {
		// The material store is outside the metadata transaction. Restore the
		// material only when the metadata row is still present; if the delete
		// actually committed and merely returned an error, restoring it would
		// leave an orphaned secret.
		if restoreErr := s.restoreMaterialIfMetadataPresent(ctx, ref, certificatePEM, privateKeyPEM); restoreErr != nil {
			return errors.Join(result.Error, restoreErr)
		}
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *GORMStore) restoreMaterialIfMetadataPresent(ctx context.Context, ref resource.Ref, certificatePEM, privateKeyPEM []byte) error {
	var current certificateRow
	lookupErr := s.db.WithContext(context.WithoutCancel(ctx)).First(&current, "ref_id = ?", ref.ID).Error
	if lookupErr != nil {
		// A missing row means the metadata delete committed. For an unknown
		// lookup failure, leave the material deleted rather than risk creating
		// an orphan secret while the metadata state is uncertain.
		return nil
	}
	return restoreCertificateMaterial(ctx, s.materials, ref, certificatePEM, privateKeyPEM)
}

func restoreCertificateMaterial(ctx context.Context, materials ProtectedMaterialStore, ref resource.Ref, certificatePEM, privateKeyPEM []byte) error {
	err := materials.Put(context.WithoutCancel(ctx), ref, certificatePEM, privateKeyPEM)
	// A failed Delete may have left the original material in place. A conflict
	// therefore means the desired post-failure state is already restored.
	if errors.Is(err, ErrConflict) {
		return nil
	}
	return err
}

func (s *GORMStore) Bundle(ctx context.Context, ref resource.Ref, includePrivate bool) (Bundle, error) {
	record, err := s.Get(ctx, ref)
	if err != nil {
		return Bundle{}, err
	}
	if !includePrivate {
		if reader, ok := s.materials.(CertificateMaterialReader); ok {
			certificatePEM, err := reader.GetCertificate(ctx, ref)
			if err != nil {
				return Bundle{}, err
			}
			return Bundle{Record: record, Certificate: certificatePEM}, nil
		}
	}
	certificatePEM, privateKeyPEM, err := s.materials.Get(ctx, ref)
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{Record: record, Certificate: certificatePEM}
	if includePrivate {
		bundle.PrivateKey = privateKeyPEM
	}
	return bundle, nil
}

// AESGCMMaterialStore is a protected SQLite material store. The encryption
// key is supplied by the application key manager and never persisted in the
// database. The row contains only an authenticated ciphertext envelope.
type AESGCMMaterialStore struct {
	db    *gorm.DB
	keyID string
	aead  cipher.AEAD
}

type materialRow struct {
	RefID                 string    `gorm:"primaryKey;size:255"`
	KeyID                 string    `gorm:"not null;size:255"`
	Nonce                 []byte    `gorm:"type:blob"` // legacy combined envelope
	Ciphertext            []byte    `gorm:"type:blob"` // legacy combined envelope
	CertificateNonce      []byte    `gorm:"type:blob"`
	CertificateCiphertext []byte    `gorm:"type:blob"`
	PrivateKeyNonce       []byte    `gorm:"type:blob"`
	PrivateKeyCiphertext  []byte    `gorm:"type:blob"`
	CreatedAt             time.Time `gorm:"not null"`
	UpdatedAt             time.Time `gorm:"not null"`
}

func (materialRow) TableName() string { return "platform_certificate_materials" }

func NewAESGCMMaterialStore(db *gorm.DB, keyID string, key []byte) (*AESGCMMaterialStore, error) {
	if db == nil || strings.TrimSpace(keyID) == "" {
		return nil, errors.New("certificate material database and key ID are required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("certificate material key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("certificate material cipher: %w", err)
	}
	if err := db.AutoMigrate(&materialRow{}); err != nil {
		return nil, fmt.Errorf("certificate material migration: %w", err)
	}
	return &AESGCMMaterialStore{db: db, keyID: keyID, aead: aead}, nil
}

func materialAAD(ref resource.Ref, keyID string) []byte {
	// Keep the original envelope AAD byte-for-byte stable so records written
	// before the certificate/key split remain decryptable after migration.
	h := sha256.New()
	_, _ = h.Write([]byte("nezha-unified/certificate/v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(ref.Kind))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(ref.ID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(keyID))
	return h.Sum(nil)
}

func materialRoleAAD(ref resource.Ref, keyID, role string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nezha-unified/certificate/v1"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(ref.Kind))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(ref.ID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(keyID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(role))
	return h.Sum(nil)
}

func encodeMaterial(certificatePEM, privateKeyPEM []byte) []byte {
	out := make([]byte, 8+len(certificatePEM)+len(privateKeyPEM))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(certificatePEM)))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(privateKeyPEM)))
	copy(out[8:], certificatePEM)
	copy(out[8+len(certificatePEM):], privateKeyPEM)
	return out
}

func decodeMaterial(data []byte) ([]byte, []byte, error) {
	if len(data) < 8 {
		return nil, nil, errors.New("invalid certificate material")
	}
	certLen, keyLen := binary.BigEndian.Uint32(data[:4]), binary.BigEndian.Uint32(data[4:8])
	if uint64(certLen)+uint64(keyLen)+8 != uint64(len(data)) {
		return nil, nil, errors.New("invalid certificate material length")
	}
	certificatePEM := append([]byte(nil), data[8:8+certLen]...)
	privateKeyPEM := append([]byte(nil), data[8+certLen:]...)
	return certificatePEM, privateKeyPEM, nil
}

func (s *AESGCMMaterialStore) Put(ctx context.Context, ref resource.Ref, certificatePEM, privateKeyPEM []byte) error {
	if s == nil || s.db == nil || s.aead == nil || ref.Kind != resource.Certificate || ref.Validate() != nil || len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return ErrInvalidCertificate
	}
	certificateNonce := make([]byte, s.aead.NonceSize())
	privateKeyNonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, certificateNonce); err != nil {
		return err
	}
	if _, err := io.ReadFull(rand.Reader, privateKeyNonce); err != nil {
		return err
	}
	certificateCiphertext := s.aead.Seal(nil, certificateNonce, certificatePEM, materialRoleAAD(ref, s.keyID, "certificate"))
	privateKeyCiphertext := s.aead.Seal(nil, privateKeyNonce, privateKeyPEM, materialRoleAAD(ref, s.keyID, "private-key"))
	now := time.Now().UTC()
	err := s.db.WithContext(ctx).Create(&materialRow{RefID: ref.ID, KeyID: s.keyID, CertificateNonce: certificateNonce, CertificateCiphertext: certificateCiphertext, PrivateKeyNonce: privateKeyNonce, PrivateKeyCiphertext: privateKeyCiphertext, CreatedAt: now, UpdatedAt: now}).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrConflict
	}
	return err
}

func (s *AESGCMMaterialStore) Get(ctx context.Context, ref resource.Ref) ([]byte, []byte, error) {
	if s == nil || s.db == nil || s.aead == nil || ref.Kind != resource.Certificate || ref.Validate() != nil {
		return nil, nil, ErrNotFound
	}
	var row materialRow
	if err := s.db.WithContext(ctx).First(&row, "ref_id = ?", ref.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	if row.KeyID != s.keyID {
		return nil, nil, errors.New("certificate material key is unavailable")
	}
	if len(row.CertificateCiphertext) > 0 || len(row.PrivateKeyCiphertext) > 0 {
		certificatePEM, err := s.decryptPart(ref, row.KeyID, row.CertificateNonce, row.CertificateCiphertext, "certificate")
		if err != nil {
			return nil, nil, err
		}
		privateKeyPEM, err := s.decryptPart(ref, row.KeyID, row.PrivateKeyNonce, row.PrivateKeyCiphertext, "private-key")
		if err != nil {
			clear(certificatePEM)
			return nil, nil, err
		}
		return certificatePEM, privateKeyPEM, nil
	}
	if len(row.Nonce) != s.aead.NonceSize() {
		return nil, nil, errors.New("certificate material nonce is invalid")
	}
	plaintext, err := s.aead.Open(nil, row.Nonce, row.Ciphertext, materialAAD(ref, row.KeyID))
	if err != nil {
		return nil, nil, errors.New("certificate material authentication failed")
	}
	certificatePEM, privateKeyPEM, err := decodeMaterial(plaintext)
	clear(plaintext)
	if err != nil {
		return nil, nil, err
	}
	return certificatePEM, privateKeyPEM, nil
}

func (s *AESGCMMaterialStore) GetCertificate(ctx context.Context, ref resource.Ref) ([]byte, error) {
	if s == nil || s.db == nil || s.aead == nil || ref.Kind != resource.Certificate || ref.Validate() != nil {
		return nil, ErrNotFound
	}
	var row materialRow
	// Public-only downloads must not select the encrypted private-key columns.
	// Legacy rows still need the combined envelope fields for the compatibility
	// fallback below.
	if err := s.db.WithContext(ctx).
		Select("ref_id", "key_id", "nonce", "ciphertext", "certificate_nonce", "certificate_ciphertext", "created_at", "updated_at").
		First(&row, "ref_id = ?", ref.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if row.KeyID != s.keyID {
		return nil, errors.New("certificate material key is unavailable")
	}
	if len(row.CertificateCiphertext) == 0 {
		certificatePEM, _, err := s.Get(ctx, ref)
		return certificatePEM, err
	}
	return s.decryptPart(ref, row.KeyID, row.CertificateNonce, row.CertificateCiphertext, "certificate")
}

func (s *AESGCMMaterialStore) decryptPart(ref resource.Ref, keyID string, nonce, ciphertext []byte, role string) ([]byte, error) {
	if len(nonce) != s.aead.NonceSize() || len(ciphertext) < s.aead.Overhead() {
		return nil, errors.New("certificate material envelope is invalid")
	}
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, materialRoleAAD(ref, keyID, role))
	if err != nil {
		return nil, errors.New("certificate material authentication failed")
	}
	return plaintext, nil
}

func (s *AESGCMMaterialStore) Delete(ctx context.Context, ref resource.Ref) error {
	if s == nil || s.db == nil || ref.Kind != resource.Certificate || ref.Validate() != nil {
		return ErrNotFound
	}
	result := s.db.WithContext(ctx).Delete(&materialRow{}, "ref_id = ?", ref.ID)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// MaterialFingerprint is intended for diagnostics and tests only. It exposes
// no certificate or key bytes and is safe to compare across storage reads.
func MaterialFingerprint(certificatePEM, privateKeyPEM []byte) string {
	h := sha256.New()
	_, _ = h.Write(certificatePEM)
	_, _ = h.Write(privateKeyPEM)
	return hex.EncodeToString(h.Sum(nil))
}
