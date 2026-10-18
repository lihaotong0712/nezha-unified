package resource

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// ErrNotFound reports that a resource is not registered (or has been removed).
var ErrNotFound = gorm.ErrRecordNotFound

// ErrConflict reports an optimistic-concurrency or uniqueness conflict.
var ErrConflict = errors.New("resource conflict")

// Store persists the authoritative cross-module resource projection.
type Store interface {
	Create(context.Context, Metadata) error
	Get(context.Context, Ref) (Metadata, error)
	Update(context.Context, Metadata, uint64) (Metadata, error)
	Delete(context.Context, Ref, uint64) error
	List(context.Context, uint64, State) ([]Metadata, error)
}

type metadataRow struct {
	Kind      string     `gorm:"primaryKey;column:kind"`
	RefID     string     `gorm:"primaryKey;column:ref_id"`
	OwnerID   uint64     `gorm:"not null;index"`
	Revision  uint64     `gorm:"not null"`
	State     string     `gorm:"not null;index"`
	CreatedAt time.Time  `gorm:"not null"`
	UpdatedAt time.Time  `gorm:"not null"`
	DeletedAt *time.Time `gorm:"index"`
}

func (metadataRow) TableName() string { return "platform_resources" }

// GORMStore is a SQLite-friendly implementation of Store. It uses an explicit
// soft-delete column so deleted rows remain visible to conflict checks.
type GORMStore struct{ db *gorm.DB }

// NewGORMStore creates the resource registry and runs its additive migration.
func NewGORMStore(db *gorm.DB) (*GORMStore, error) {
	if db == nil {
		return nil, errors.New("resource: nil database")
	}
	if err := db.AutoMigrate(&metadataRow{}); err != nil {
		return nil, fmt.Errorf("resource migration: %w", err)
	}
	return &GORMStore{db: db}, nil
}

func validateMetadata(m Metadata) error {
	if err := m.Ref.Validate(); err != nil || m.OwnerID == 0 || m.Revision == 0 {
		return ErrInvalidRef
	}
	switch m.State {
	case Pending, Active, Disabled, Deleted:
	default:
		return errors.New("invalid resource state")
	}
	return nil
}

func rowFromMetadata(m Metadata) metadataRow {
	return metadataRow{Kind: string(m.Ref.Kind), RefID: m.Ref.ID, OwnerID: m.OwnerID, Revision: m.Revision, State: string(m.State), CreatedAt: m.CreatedAt.UTC(), UpdatedAt: m.UpdatedAt.UTC(), DeletedAt: m.DeletedAt}
}

func metadataFromRow(r metadataRow) Metadata {
	return Metadata{Ref: Ref{Kind: Kind(r.Kind), ID: r.RefID}, OwnerID: r.OwnerID, Revision: r.Revision, State: State(r.State), CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), DeletedAt: r.DeletedAt}
}

func (s *GORMStore) Create(ctx context.Context, m Metadata) error {
	if err := validateMetadata(m); err != nil {
		return err
	}
	now := time.Now().UTC()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = m.CreatedAt
	}
	row := rowFromMetadata(m)
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		var existing metadataRow
		if queryErr := s.db.WithContext(ctx).Where("kind = ? AND ref_id = ?", row.Kind, row.RefID).First(&existing).Error; queryErr == nil {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (s *GORMStore) Get(ctx context.Context, ref Ref) (Metadata, error) {
	if err := ref.Validate(); err != nil {
		return Metadata{}, err
	}
	var row metadataRow
	if err := s.db.WithContext(ctx).Where("kind = ? AND ref_id = ?", string(ref.Kind), ref.ID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Metadata{}, ErrNotFound
		}
		return Metadata{}, err
	}
	return metadataFromRow(row), nil
}

// Update changes metadata only when expectedRevision is still current and bumps
// the persisted revision exactly once. It returns the new authoritative value.
func (s *GORMStore) Update(ctx context.Context, m Metadata, expectedRevision uint64) (Metadata, error) {
	if err := validateMetadata(m); err != nil {
		return Metadata{}, err
	}
	if expectedRevision == 0 || expectedRevision == ^uint64(0) {
		return Metadata{}, ErrConflict
	}
	now := time.Now().UTC()
	q := s.db.WithContext(ctx).Model(&metadataRow{}).
		Where("kind = ? AND ref_id = ? AND revision = ?", string(m.Ref.Kind), m.Ref.ID, expectedRevision).
		Updates(map[string]any{"owner_id": m.OwnerID, "state": string(m.State), "revision": expectedRevision + 1, "updated_at": now, "deleted_at": m.DeletedAt})
	if q.Error != nil {
		return Metadata{}, q.Error
	}
	if q.RowsAffected != 1 {
		var row metadataRow
		err := s.db.WithContext(ctx).Where("kind = ? AND ref_id = ?", string(m.Ref.Kind), m.Ref.ID).First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Metadata{}, ErrNotFound
		}
		if err != nil {
			return Metadata{}, err
		}
		return Metadata{}, ErrConflict
	}
	return s.Get(ctx, m.Ref)
}

func (s *GORMStore) Delete(ctx context.Context, ref Ref, expectedRevision uint64) error {
	if ref.Validate() != nil || expectedRevision == 0 || expectedRevision == ^uint64(0) {
		return ErrInvalidRef
	}
	now := time.Now().UTC()
	q := s.db.WithContext(ctx).Model(&metadataRow{}).
		Where("kind = ? AND ref_id = ? AND revision = ?", string(ref.Kind), ref.ID, expectedRevision).
		Updates(map[string]any{"state": string(Deleted), "deleted_at": now, "updated_at": now, "revision": expectedRevision + 1})
	if q.Error != nil {
		return q.Error
	}
	if q.RowsAffected == 1 {
		return nil
	}
	var row metadataRow
	err := s.db.WithContext(ctx).Where("kind = ? AND ref_id = ?", string(ref.Kind), ref.ID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return ErrConflict
}

func (s *GORMStore) List(ctx context.Context, ownerID uint64, state State) ([]Metadata, error) {
	if ownerID == 0 {
		return nil, ErrInvalidRef
	}
	query := s.db.WithContext(ctx).Where("owner_id = ?", ownerID)
	if strings.TrimSpace(string(state)) != "" {
		switch state {
		case Pending, Active, Disabled, Deleted:
		default:
			return nil, errors.New("invalid resource state")
		}
		query = query.Where("state = ?", string(state))
	}
	var rows []metadataRow
	if err := query.Order("kind, ref_id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Metadata, 0, len(rows))
	for _, row := range rows {
		out = append(out, metadataFromRow(row))
	}
	return out, nil
}
