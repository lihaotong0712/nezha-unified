package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/gorm"
)

var (
	ErrConflict = errors.New("audit event conflict")
	ErrNotFound = gorm.ErrRecordNotFound
)

type eventRow struct {
	ID                string    `gorm:"primaryKey;type:varchar(255)"`
	EventTime         time.Time `gorm:"not null;index"`
	OperationID       string    `gorm:"not null;index"`
	SubjectKind       string    `gorm:"not null;index"`
	SubjectID         string    `gorm:"not null"`
	TriggeredByKind   string    `gorm:"not null"`
	TriggeredByID     string    `gorm:"not null"`
	Entry             string    `gorm:"not null"`
	TokenID           uint64    `gorm:"index"`
	SourceGrantID     string    `gorm:"type:varchar(255)"`
	Action            string    `gorm:"not null;index"`
	ResourceKind      string    `gorm:"not null;index"`
	ResourceID        string    `gorm:"not null"`
	Outcome           string    `gorm:"not null;index"`
	Code              string    `gorm:"type:varchar(64)"`
	PolicyVersion     string    `gorm:"type:varchar(255)"`
	GrantIDsJSON      string    `gorm:"type:text"`
	CredentialKind    string    `gorm:"type:varchar(64)"`
	CredentialID      string    `gorm:"type:varchar(255)"`
	CredentialVersion uint64    `gorm:"index"`
	ResourceRevision  uint64    `gorm:"index"`
	Fingerprint       string    `gorm:"not null;type:char(64)"`
}

func (eventRow) TableName() string { return "platform_audit_events" }

// Recorder is an append-only recorder. Event IDs are unique; replaying the
// same exact event is successful, while reusing an ID for different content is
// an explicit conflict so callers cannot silently lose an audit record.
type GORMRecorder struct{ db *gorm.DB }

func NewGORMRecorder(db *gorm.DB) (*GORMRecorder, error) {
	if db == nil {
		return nil, errors.New("audit: nil database")
	}
	if err := db.AutoMigrate(&eventRow{}); err != nil {
		return nil, fmt.Errorf("audit migration: %w", err)
	}
	return &GORMRecorder{db: db}, nil
}

func validateEvent(e Event) error {
	if strings.TrimSpace(e.ID) == "" || len(e.ID) > 255 || e.Execution.Validate() != nil || !validAction(e.Action) || e.Resource.Validate() != nil {
		return errors.New("invalid audit event")
	}
	switch e.Outcome {
	case Requested, Succeeded, Denied, Failed, Canceled:
	default:
		return errors.New("invalid audit outcome")
	}
	if e.Credential != nil && (e.Credential.Kind != resource.Credential || e.Credential.Validate() != nil) {
		return errors.New("invalid audit credential")
	}
	if e.Credential == nil && e.CredentialVersion != 0 {
		return errors.New("credential version without credential")
	}
	return nil
}

func canonicalEvent(e Event) ([]byte, error) {
	if e.Time.IsZero() {
		e.Time = time.Unix(0, 0).UTC()
	} else {
		e.Time = e.Time.UTC()
	}
	// Sort a copy so semantically equivalent grant sets have one fingerprint.
	if len(e.GrantIDs) > 1 {
		e.GrantIDs = append([]string(nil), e.GrantIDs...)
		sort.Strings(e.GrantIDs)
	}
	return json.Marshal(e)
}

func rowFromEvent(e Event) (eventRow, error) {
	encoded, err := canonicalEvent(e)
	if err != nil {
		return eventRow{}, err
	}
	var grantJSON []byte
	if e.GrantIDs != nil {
		grantJSON, err = json.Marshal(e.GrantIDs)
		if err != nil {
			return eventRow{}, err
		}
	}
	row := eventRow{ID: e.ID, EventTime: e.Time.UTC(), OperationID: e.Execution.OperationID, SubjectKind: string(e.Execution.Subject.Kind), SubjectID: e.Execution.Subject.ID, TriggeredByKind: string(e.Execution.TriggeredBy.Kind), TriggeredByID: e.Execution.TriggeredBy.ID, Entry: string(e.Execution.Entry), TokenID: e.Execution.TokenID, SourceGrantID: e.Execution.SourceGrantID, Action: string(e.Action), ResourceKind: string(e.Resource.Kind), ResourceID: e.Resource.ID, Outcome: string(e.Outcome), Code: string(e.Code), PolicyVersion: e.PolicyVersion, GrantIDsJSON: string(grantJSON), CredentialVersion: e.CredentialVersion, ResourceRevision: e.ResourceRevision}
	if e.Credential != nil {
		row.CredentialKind, row.CredentialID = string(e.Credential.Kind), e.Credential.ID
	}
	hash := sha256.Sum256(encoded)
	row.Fingerprint = hex.EncodeToString(hash[:])
	return row, nil
}

func eventFromRow(r eventRow) (Event, error) {
	e := Event{ID: r.ID, Time: r.EventTime.UTC(), Execution: authz.Execution{Subject: authz.Principal{Kind: authz.PrincipalKind(r.SubjectKind), ID: r.SubjectID}, TriggeredBy: authz.Principal{Kind: authz.PrincipalKind(r.TriggeredByKind), ID: r.TriggeredByID}, Entry: authz.Entry(r.Entry), TokenID: r.TokenID, SourceGrantID: r.SourceGrantID, OperationID: r.OperationID}, Action: authz.Action(r.Action), Resource: resource.Ref{Kind: resource.Kind(r.ResourceKind), ID: r.ResourceID}, Outcome: Outcome(r.Outcome), Code: platformerr.Code(r.Code), PolicyVersion: r.PolicyVersion, CredentialVersion: r.CredentialVersion, ResourceRevision: r.ResourceRevision}
	if r.GrantIDsJSON != "" {
		if err := json.Unmarshal([]byte(r.GrantIDsJSON), &e.GrantIDs); err != nil {
			return Event{}, err
		}
	}
	if r.CredentialID != "" {
		e.Credential = &resource.Ref{Kind: resource.Kind(r.CredentialKind), ID: r.CredentialID}
	}
	return e, nil
}

func (r *GORMRecorder) Record(ctx context.Context, event Event) error {
	if err := validateEvent(event); err != nil {
		return err
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	row, err := rowFromEvent(event)
	if err != nil {
		return err
	}
	if err := r.db.WithContext(ctx).Create(&row).Error; err == nil {
		return nil
	}
	var existing eventRow
	if queryErr := r.db.WithContext(ctx).First(&existing, "id = ?", event.ID).Error; errors.Is(queryErr, gorm.ErrRecordNotFound) {
		return queryErr
	} else if queryErr != nil {
		return queryErr
	}
	if existing.Fingerprint == row.Fingerprint {
		return nil
	}
	return ErrConflict
}

func (r *GORMRecorder) Get(ctx context.Context, id string) (Event, error) {
	if strings.TrimSpace(id) == "" {
		return Event{}, ErrNotFound
	}
	var row eventRow
	if err := r.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		return Event{}, err
	}
	return eventFromRow(row)
}

// ListByOperation returns attempts in event-time order for an operation.
func (r *GORMRecorder) ListByOperation(ctx context.Context, operationID string) ([]Event, error) {
	if strings.TrimSpace(operationID) == "" {
		return nil, errors.New("empty operation ID")
	}
	var rows []eventRow
	if err := r.db.WithContext(ctx).Where("operation_id = ?", operationID).Order("event_time, id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(rows))
	for _, row := range rows {
		event, err := eventFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, nil
}

func validAction(action authz.Action) bool {
	switch action {
	case authz.View, authz.Edit, authz.Execute, authz.Export, authz.Download, authz.Delete, authz.Use, authz.Reveal, authz.Rotate, authz.Grant:
		return true
	default:
		return false
	}
}
