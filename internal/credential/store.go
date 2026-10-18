package credential

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/gorm"
)

var (
	ErrCredentialNotFound   = errors.New("credential not found")
	ErrCredentialDisabled   = errors.New("credential is disabled")
	ErrCredentialDeleted    = errors.New("credential is deleted")
	ErrVersionRevoked       = errors.New("credential version is revoked")
	ErrBindingMismatch      = errors.New("credential binding does not match")
	ErrCredentialType       = errors.New("credential type does not match")
	ErrAuthorizationMissing = errors.New("credential authorizer is unavailable")
	ErrAuditMissing         = errors.New("credential audit recorder is unavailable")
	ErrAuditFailed          = errors.New("credential audit record failed")
	ErrInvalidCredential    = errors.New("invalid credential")
	ErrResourceMismatch     = errors.New("credential resource registry returned invalid metadata")
)

const (
	credentialActive   = "active"
	credentialDisabled = "disabled"
	credentialDeleted  = "deleted"
	versionActive      = "active"
	versionRevoked     = "revoked"
)

// Record and VersionRecord are intentionally internal storage envelopes. Use
// Metadata and WithSecret at module boundaries so encrypted bytes can never be
// accidentally serialized as API output.
type Record struct {
	ID             string `gorm:"primaryKey;size:255"`
	OwnerID        uint64 `gorm:"index;not null"`
	Name           string `gorm:"size:255;not null"`
	Type           string `gorm:"size:255;not null"`
	State          string `gorm:"size:32;index;not null"`
	CurrentVersion uint64 `gorm:"not null"`
	Revision       uint64 `gorm:"not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time `gorm:"index"`
}

type BindingRecord struct {
	ID           uint64 `gorm:"primaryKey"`
	CredentialID string `gorm:"size:255;index;not null"`
	Purpose      string `gorm:"size:64;not null"`
	ConsumerKind string `gorm:"size:64;not null"`
	ConsumerID   string `gorm:"size:255;not null"`
	TargetKind   string `gorm:"size:64;not null"`
	TargetID     string `gorm:"size:255;not null"`
}

type VersionRecord struct {
	CredentialID string `gorm:"primaryKey;size:255"`
	Version      uint64 `gorm:"primaryKey"`
	State        string `gorm:"size:32;index;not null"`
	KeyID        string `gorm:"size:255;not null"`
	Algorithm    string `gorm:"size:32;not null"`
	Nonce        []byte `gorm:"type:blob;not null"`
	Ciphertext   []byte `gorm:"type:blob;not null"`
	CreatedAt    time.Time
	RevokedAt    *time.Time `gorm:"index"`
}

func (Record) TableName() string        { return "platform_credentials" }
func (BindingRecord) TableName() string { return "platform_credential_bindings" }
func (VersionRecord) TableName() string { return "platform_credential_versions" }

type CreateRequest struct {
	ID       string
	OwnerID  uint64
	Name     string
	Type     Type
	Bindings []Binding
	Secret   *Secret
}

type RotateRequest struct {
	Credential Ref
	Secret     *Secret
}

type Store struct {
	db         *gorm.DB
	protector  Protector
	authorizer authz.Authorizer
	mu         sync.RWMutex
	recorder   audit.Recorder
	lookup     ResourceLookup
}

// ResourceLookup is implemented by the authoritative platform registry. It
// deliberately mirrors the narrow read method instead of importing the
// registry package, which keeps the credential package dependency-free.
type ResourceLookup interface {
	Get(context.Context, resource.Ref) (resource.Metadata, error)
}

// NewStore accepts an optional authorizer to keep construction convenient for
// migrations and tests. WithSecret always fails closed when it is absent.
func NewStore(db *gorm.DB, protector Protector, authorizers ...authz.Authorizer) *Store {
	var authorizer authz.Authorizer
	if len(authorizers) != 0 {
		authorizer = authorizers[0]
	}
	return &Store{db: db, protector: protector, authorizer: authorizer}
}

func (s *Store) SetAuthorizer(authorizer authz.Authorizer) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.authorizer = authorizer
	s.mu.Unlock()
}

func (s *Store) SetRecorder(recorder audit.Recorder) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.recorder = recorder
	s.mu.Unlock()
}

// SetResourceLookup connects the authoritative platform registry. When set,
// local owner/state values are projections and never override that registry.
func (s *Store) SetResourceLookup(lookup ResourceLookup) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.lookup = lookup
	s.mu.Unlock()
}

func (s *Store) Migrate(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("credential database is unavailable")
	}
	return s.db.WithContext(ctx).AutoMigrate(&Record{}, &BindingRecord{}, &VersionRecord{})
}

func (s *Store) Create(ctx context.Context, input CreateRequest) (Metadata, error) {
	if s == nil || s.db == nil || s.protector == nil || input.Secret == nil {
		return Metadata{}, ErrInvalidCredential
	}
	defer input.Secret.Destroy()
	if err := contextErr(ctx); err != nil {
		return Metadata{}, err
	}
	id := strings.TrimSpace(input.ID)
	if id == "" {
		var err error
		id, err = randomID("cred-")
		if err != nil {
			return Metadata{}, err
		}
	}
	if (resource.Ref{Kind: resource.Credential, ID: id}).Validate() != nil || input.OwnerID == 0 || strings.TrimSpace(input.Name) == "" || strings.TrimSpace(string(input.Type)) == "" || !validBindings(input.Bindings) {
		return Metadata{}, ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := resource.Ref{Kind: resource.Credential, ID: id}
	encrypted, err := s.protector.Seal(ctx, ref, 1, input.Secret)
	if err != nil {
		return Metadata{}, err
	}
	now := time.Now().UTC()
	record := Record{ID: id, OwnerID: input.OwnerID, Name: input.Name, Type: string(input.Type), State: credentialActive, CurrentVersion: 1, Revision: 1, CreatedAt: now, UpdatedAt: now}
	version := VersionRecord{CredentialID: id, Version: 1, State: versionActive, KeyID: encrypted.KeyID, Algorithm: encrypted.Algorithm, Nonce: append([]byte(nil), encrypted.Nonce...), Ciphertext: append([]byte(nil), encrypted.Ciphertext...), CreatedAt: now}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&record).Error; err != nil {
			return err
		}
		for _, binding := range input.Bindings {
			binding := bindingRecord(id, binding)
			if err := tx.Create(&binding).Error; err != nil {
				return err
			}
		}
		return tx.Create(&version).Error
	})
	if err != nil {
		return Metadata{}, err
	}
	return metadataFromRecord(record, input.Bindings), nil
}

func (s *Store) Rotate(ctx context.Context, input RotateRequest) (uint64, error) {
	if s == nil || s.db == nil || s.protector == nil || input.Secret == nil || input.Credential.ID == "" {
		return 0, ErrInvalidCredential
	}
	defer input.Secret.Destroy()
	s.mu.Lock()
	defer s.mu.Unlock()
	var record Record
	if err := s.db.WithContext(ctx).First(&record, "id = ?", input.Credential.ID).Error; err != nil {
		return 0, translateNotFound(err)
	}
	if record.State == credentialDeleted {
		return 0, ErrCredentialDeleted
	}
	if record.State != credentialActive {
		return 0, ErrCredentialDisabled
	}
	version := record.CurrentVersion + 1
	ref := resource.Ref{Kind: resource.Credential, ID: record.ID}
	encrypted, err := s.protector.Seal(ctx, ref, version, input.Secret)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	newVersion := VersionRecord{CredentialID: record.ID, Version: version, State: versionActive, KeyID: encrypted.KeyID, Algorithm: encrypted.Algorithm, Nonce: append([]byte(nil), encrypted.Nonce...), Ciphertext: append([]byte(nil), encrypted.Ciphertext...), CreatedAt: now}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&newVersion).Error; err != nil {
			return err
		}
		return tx.Model(&Record{}).Where("id = ?", record.ID).Updates(map[string]any{"current_version": version, "revision": record.Revision + 1, "updated_at": now}).Error
	})
	return version, err
}

func (s *Store) RevokeVersion(ctx context.Context, ref Ref) error {
	if s == nil || s.db == nil {
		return ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref.ID == "" || ref.Version == 0 {
		return ErrInvalidCredential
	}
	now := time.Now().UTC()
	result := s.db.WithContext(ctx).Model(&VersionRecord{}).Where("credential_id = ? AND version = ? AND state = ?", ref.ID, ref.Version, versionActive).Updates(map[string]any{"state": versionRevoked, "revoked_at": now})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		var count int64
		if err := s.db.WithContext(ctx).Model(&VersionRecord{}).Where("credential_id = ? AND version = ?", ref.ID, ref.Version).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return ErrCredentialNotFound
		}
		return ErrVersionRevoked
	}
	return nil
}

func (s *Store) SetState(ctx context.Context, ref Ref, state resource.State) error {
	if s == nil || s.db == nil {
		return ErrInvalidCredential
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref.Version != 0 || (resource.Ref{Kind: resource.Credential, ID: ref.ID}).Validate() != nil {
		return ErrInvalidCredential
	}
	var value string
	switch state {
	case resource.Active:
		value = credentialActive
	case resource.Disabled:
		value = credentialDisabled
	case resource.Deleted:
		value = credentialDeleted
	default:
		return ErrInvalidCredential
	}
	var record Record
	if err := s.db.WithContext(ctx).First(&record, "id = ?", ref.ID).Error; err != nil {
		return translateNotFound(err)
	}
	if record.State == credentialDeleted && value != credentialDeleted {
		return ErrCredentialDeleted
	}
	now := time.Now().UTC()
	updates := map[string]any{"state": value, "revision": record.Revision + 1, "updated_at": now}
	if value == credentialDeleted {
		updates["deleted_at"] = now
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Record{}).Where("id = ?", ref.ID).Updates(updates).Error; err != nil {
			return err
		}
		if value == credentialDeleted {
			return tx.Model(&VersionRecord{}).Where("credential_id = ? AND state = ?", ref.ID, versionActive).Updates(map[string]any{"state": versionRevoked, "revoked_at": now}).Error
		}
		return nil
	})
}

func (s *Store) Disable(ctx context.Context, ref Ref) error {
	return s.SetState(ctx, ref, resource.Disabled)
}
func (s *Store) Enable(ctx context.Context, ref Ref) error {
	return s.SetState(ctx, ref, resource.Active)
}
func (s *Store) Delete(ctx context.Context, ref Ref) error {
	return s.SetState(ctx, ref, resource.Deleted)
}

func (s *Store) Metadata(ctx context.Context, id string) (Metadata, error) {
	if s == nil || s.db == nil {
		return Metadata{}, ErrInvalidCredential
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var record Record
	if err := s.db.WithContext(ctx).First(&record, "id = ?", id).Error; err != nil {
		return Metadata{}, translateNotFound(err)
	}
	var bindings []BindingRecord
	if err := s.db.WithContext(ctx).Where("credential_id = ?", id).Find(&bindings).Error; err != nil {
		return Metadata{}, err
	}
	return s.projectMetadata(ctx, record, bindingsToValues(bindings))
}

func (s *Store) ListMetadata(ctx context.Context, ownerID uint64) ([]Metadata, error) {
	if s == nil || s.db == nil {
		return nil, ErrInvalidCredential
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := s.db.WithContext(ctx).Order("created_at ASC")
	if ownerID != 0 && s.lookup == nil {
		query = query.Where("owner_id = ?", ownerID)
	}
	var records []Record
	if err := query.Find(&records).Error; err != nil {
		return nil, err
	}
	result := make([]Metadata, 0, len(records))
	for _, record := range records {
		var bindings []BindingRecord
		if err := s.db.WithContext(ctx).Where("credential_id = ?", record.ID).Find(&bindings).Error; err != nil {
			return nil, err
		}
		metadata, err := s.projectMetadata(ctx, record, bindingsToValues(bindings))
		if err != nil {
			return nil, err
		}
		if ownerID == 0 || metadata.Resource.OwnerID == ownerID {
			result = append(result, metadata)
		}
	}
	return result, nil
}

func (s *Store) WithSecret(ctx context.Context, request UseRequest, fn func(context.Context, Resolved) error) (err error) {
	if fn == nil || s == nil || s.db == nil || s.protector == nil {
		return ErrInvalidCredential
	}
	if err := request.Validate(); err != nil {
		return ErrInvalidCredential
	}
	s.mu.RLock()
	authorizer := s.authorizer
	recorder := s.recorder
	s.mu.RUnlock()
	if authorizer == nil {
		return ErrAuthorizationMissing
	}
	if recorder == nil {
		return ErrAuditMissing
	}
	checks := []authz.Request{
		{Execution: request.Execution, Action: authz.Use, Resource: request.Credential.Resource()},
		{Execution: request.Execution, Action: authz.Use, Resource: request.Binding.Consumer},
		{Execution: request.Execution, Action: request.Action, Resource: request.Binding.Target, DNS: request.DNS, CertificateNames: request.CertificateNames},
	}
	for _, check := range checks {
		if _, err := authz.Check(ctx, authorizer, check); err != nil {
			return err
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lookup != nil {
		metadata, err := s.lookup.Get(ctx, request.Credential.Resource())
		if err != nil {
			return err
		}
		if metadata.Ref != request.Credential.Resource() {
			return ErrResourceMismatch
		}
		if !metadata.Executable() {
			return ErrCredentialDisabled
		}
	}
	var record Record
	if err := s.db.WithContext(ctx).First(&record, "id = ?", request.Credential.ID).Error; err != nil {
		return translateNotFound(err)
	}
	if record.State == credentialDeleted {
		return ErrCredentialDeleted
	}
	if record.State != credentialActive {
		return ErrCredentialDisabled
	}
	if Type(record.Type) != request.ExpectedType {
		return ErrCredentialType
	}
	version := request.Credential.Version
	if version == 0 {
		version = record.CurrentVersion
	}
	var versionRecord VersionRecord
	if err := s.db.WithContext(ctx).First(&versionRecord, "credential_id = ? AND version = ?", record.ID, version).Error; err != nil {
		return translateNotFound(err)
	}
	if versionRecord.State != versionActive {
		return ErrVersionRevoked
	}
	var bindings []BindingRecord
	if err := s.db.WithContext(ctx).Where("credential_id = ?", record.ID).Find(&bindings).Error; err != nil {
		return err
	}
	if !bindingAllowed(request.Binding, bindingsToValues(bindings)) {
		return ErrBindingMismatch
	}
	if recorder != nil {
		eventID, eventErr := randomID("credential-use-")
		if eventErr != nil {
			return eventErr
		}
		ref := request.Credential.Resource()
		event := audit.Event{ID: eventID + "-requested", Time: time.Now().UTC(), Execution: request.Execution, Action: authz.Use, Resource: ref, Outcome: audit.Requested, Credential: &ref, CredentialVersion: version, ResourceRevision: record.Revision}
		if recordErr := recorder.Record(ctx, event); recordErr != nil {
			return ErrAuditFailed
		}
		defer func() {
			event.ID = eventID + "-finished"
			event.Time = time.Now().UTC()
			event.Outcome = audit.Succeeded
			if err != nil {
				event.Outcome, event.Code = audit.Failed, platformerr.Internal
			}
			if recovered := recover(); recovered != nil {
				event.Outcome, event.Code = audit.Failed, platformerr.Internal
				_ = recorder.Record(context.WithoutCancel(ctx), event)
				panic(recovered)
			}
			if recordErr := recorder.Record(context.WithoutCancel(ctx), event); recordErr != nil {
				err = ErrAuditFailed
			}
		}()
	}
	secret, err := s.protector.Open(ctx, resource.Ref{Kind: resource.Credential, ID: record.ID}, version, EncryptedSecret{KeyID: versionRecord.KeyID, Algorithm: versionRecord.Algorithm, Nonce: append([]byte(nil), versionRecord.Nonce...), Ciphertext: append([]byte(nil), versionRecord.Ciphertext...)})
	if err != nil {
		return err
	}
	defer secret.Destroy()
	return fn(ctx, Resolved{Version: version, Type: Type(record.Type), Secret: secret})
}

func validBindings(bindings []Binding) bool {
	for _, binding := range bindings {
		if !validBinding(binding) {
			return false
		}
	}
	return true
}

func validBinding(binding Binding) bool {
	if binding.Consumer.Validate() != nil || binding.Target.Validate() != nil {
		return false
	}
	switch binding.Purpose {
	case DNSManage, DNSChallenge, CertificateIssue, CertificateDeploy, NotificationSend:
		return true
	default:
		return false
	}
}

func bindingRecord(credentialID string, binding Binding) BindingRecord {
	return BindingRecord{CredentialID: credentialID, Purpose: string(binding.Purpose), ConsumerKind: string(binding.Consumer.Kind), ConsumerID: binding.Consumer.ID, TargetKind: string(binding.Target.Kind), TargetID: binding.Target.ID}
}

func bindingValue(record BindingRecord) Binding {
	return Binding{Purpose: Purpose(record.Purpose), Consumer: resource.Ref{Kind: resource.Kind(record.ConsumerKind), ID: record.ConsumerID}, Target: resource.Ref{Kind: resource.Kind(record.TargetKind), ID: record.TargetID}}
}

func bindingsToValues(records []BindingRecord) []Binding {
	result := make([]Binding, 0, len(records))
	for _, record := range records {
		result = append(result, bindingValue(record))
	}
	return result
}

func bindingAllowed(request Binding, bindings []Binding) bool {
	for _, binding := range bindings {
		if binding == request {
			return true
		}
	}
	return false
}

func metadataFromRecord(record Record, bindings []Binding) Metadata {
	state := resource.State(record.State)
	if state == "" {
		state = resource.Pending
	}
	return Metadata{Resource: resource.Metadata{Ref: resource.Ref{Kind: resource.Credential, ID: record.ID}, OwnerID: record.OwnerID, Revision: record.Revision, State: state, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, DeletedAt: record.DeletedAt}, Name: record.Name, Type: Type(record.Type), CurrentVersion: record.CurrentVersion, Bindings: bindings}
}

func (s *Store) projectMetadata(ctx context.Context, record Record, bindings []Binding) (Metadata, error) {
	metadata := metadataFromRecord(record, bindings)
	if s.lookup != nil {
		registered, err := s.lookup.Get(ctx, metadata.Resource.Ref)
		if err != nil {
			return Metadata{}, err
		}
		if registered.Ref != metadata.Resource.Ref || registered.OwnerID == 0 || registered.Revision == 0 {
			return Metadata{}, ErrResourceMismatch
		}
		metadata.Resource = registered
	}
	return metadata, nil
}

func translateNotFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrCredentialNotFound
	}
	return err
}

func randomID(prefix string) (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(id), nil
}
