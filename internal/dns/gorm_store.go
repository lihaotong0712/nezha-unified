package dns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/gorm"
)

var (
	ErrBindingNotFound = gorm.ErrRecordNotFound
	ErrBindingConflict = errors.New("DNS zone binding conflict")
)

type zoneBindingRow struct {
	RefID          string     `gorm:"primaryKey;type:varchar(255)"`
	OwnerID        uint64     `gorm:"not null;index"`
	Provider       string     `gorm:"not null;type:varchar(64)"`
	RemoteID       string     `gorm:"not null;type:varchar(255)"`
	RemoteName     string     `gorm:"not null;type:varchar(255)"`
	RemoteAccess   string     `gorm:"type:varchar(64)"`
	RemoteStatus   string     `gorm:"type:varchar(64)"`
	CredentialKind string     `gorm:"type:varchar(64)"`
	CredentialID   string     `gorm:"type:varchar(255)"`
	Revision       uint64     `gorm:"not null"`
	State          string     `gorm:"not null;index"`
	CreatedAt      time.Time  `gorm:"not null"`
	UpdatedAt      time.Time  `gorm:"not null"`
	DeletedAt      *time.Time `gorm:"index"`
}

func (zoneBindingRow) TableName() string { return "platform_dns_zone_bindings" }

type GORMStore struct{ db *gorm.DB }

func NewGORMStore(db *gorm.DB) (*GORMStore, error) {
	if db == nil {
		return nil, errors.New("DNS binding store: nil database")
	}
	if err := db.AutoMigrate(&zoneBindingRow{}); err != nil {
		return nil, fmt.Errorf("DNS binding migration: %w", err)
	}
	return &GORMStore{db: db}, nil
}

func rowFromBinding(binding ZoneBinding) zoneBindingRow {
	return zoneBindingRow{RefID: binding.Ref.ID, OwnerID: binding.OwnerID, Provider: binding.Provider, RemoteID: string(binding.Remote.ID), RemoteName: binding.Remote.Name, RemoteAccess: binding.Remote.AccessMode, RemoteStatus: binding.Remote.Status, CredentialKind: string(binding.Credential.Kind), CredentialID: binding.Credential.ID, Revision: binding.Revision, State: string(binding.State), CreatedAt: binding.CreatedAt.UTC(), UpdatedAt: binding.UpdatedAt.UTC()}
}

func bindingFromRow(row zoneBindingRow) ZoneBinding {
	var deletedState resource.State
	if row.DeletedAt != nil {
		deletedState = resource.Deleted
	}
	state := resource.State(row.State)
	if deletedState != "" {
		state = deletedState
	}
	return ZoneBinding{Ref: resource.Ref{Kind: resource.DNSZone, ID: row.RefID}, OwnerID: row.OwnerID, Provider: row.Provider, Remote: Zone{ID: ZoneID(row.RemoteID), Name: row.RemoteName, AccessMode: row.RemoteAccess, Status: row.RemoteStatus}, Credential: resource.Ref{Kind: resource.Kind(row.CredentialKind), ID: row.CredentialID}, Revision: row.Revision, State: state, CreatedAt: row.CreatedAt.UTC(), UpdatedAt: row.UpdatedAt.UTC()}
}

func (s *GORMStore) Create(ctx context.Context, binding ZoneBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if binding.CreatedAt.IsZero() {
		binding.CreatedAt = now
	}
	if binding.UpdatedAt.IsZero() {
		binding.UpdatedAt = binding.CreatedAt
	}
	row := rowFromBinding(binding)
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		var existing zoneBindingRow
		if queryErr := s.db.WithContext(ctx).First(&existing, "ref_id = ?", binding.Ref.ID).Error; queryErr == nil {
			return ErrBindingConflict
		}
		return err
	}
	return nil
}

func (s *GORMStore) Get(ctx context.Context, ref resource.Ref) (ZoneBinding, error) {
	if ref.Kind != resource.DNSZone || ref.Validate() != nil {
		return ZoneBinding{}, errors.New("invalid DNS zone reference")
	}
	var row zoneBindingRow
	if err := s.db.WithContext(ctx).Where("ref_id = ? AND deleted_at IS NULL", ref.ID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ZoneBinding{}, ErrBindingNotFound
		}
		return ZoneBinding{}, err
	}
	return bindingFromRow(row), nil
}

func (s *GORMStore) List(ctx context.Context, ownerID uint64) ([]ZoneBinding, error) {
	if ownerID == 0 {
		return nil, errors.New("invalid DNS zone owner")
	}
	var rows []zoneBindingRow
	if err := s.db.WithContext(ctx).Where("owner_id = ? AND deleted_at IS NULL", ownerID).Order("ref_id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]ZoneBinding, 0, len(rows))
	for _, row := range rows {
		out = append(out, bindingFromRow(row))
	}
	return out, nil
}
