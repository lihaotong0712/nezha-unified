package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/gorm"
)

type workflowRow struct {
	RefID          string     `gorm:"primaryKey;size:255"`
	OwnerID        uint64     `gorm:"not null;index"`
	Name           string     `gorm:"not null;size:255"`
	State          string     `gorm:"not null;index"`
	CurrentVersion uint64     `gorm:"not null"`
	Revision       uint64     `gorm:"not null"`
	CreatedAt      time.Time  `gorm:"not null"`
	UpdatedAt      time.Time  `gorm:"not null;index"`
	DeletedAt      *time.Time `gorm:"index"`
}

func (workflowRow) TableName() string { return "platform_workflows" }

type versionRow struct {
	WorkflowID  string    `gorm:"primaryKey;size:255"`
	Number      uint64    `gorm:"primaryKey"`
	State       string    `gorm:"not null;index"`
	Definition  []byte    `gorm:"not null;type:blob"`
	Digest      string    `gorm:"not null;size:64;index"`
	CreatedAt   time.Time `gorm:"not null"`
	PublishedAt *time.Time
}

func (versionRow) TableName() string { return "platform_workflow_versions" }

type runRow struct {
	RefID           string    `gorm:"primaryKey;size:255"`
	WorkflowID      string    `gorm:"not null;index"`
	Version         uint64    `gorm:"not null"`
	OwnerID         uint64    `gorm:"not null;index"`
	State           string    `gorm:"not null;index"`
	SubjectKind     string    `gorm:"not null"`
	SubjectID       string    `gorm:"not null"`
	TriggeredByKind string    `gorm:"not null"`
	TriggeredByID   string    `gorm:"not null"`
	Entry           string    `gorm:"not null"`
	TokenID         uint64    `gorm:"index"`
	SourceGrantID   string    `gorm:"size:255"`
	OperationID     string    `gorm:"not null;index"`
	Definition      []byte    `gorm:"not null;type:blob"`
	Digest          string    `gorm:"not null;size:64"`
	ErrorCode       string    `gorm:"size:64"`
	ErrorMessage    string    `gorm:"size:1024"`
	Revision        uint64    `gorm:"not null"`
	CreatedAt       time.Time `gorm:"not null;index"`
	StartedAt       *time.Time
	FinishedAt      *time.Time
	UpdatedAt       time.Time `gorm:"not null;index"`
}

func (runRow) TableName() string { return "platform_workflow_runs" }

type GORMStore struct{ db *gorm.DB }

func NewGORMStore(db *gorm.DB) (*GORMStore, error) {
	if db == nil {
		return nil, errors.New("workflow: nil database")
	}
	if err := db.AutoMigrate(&workflowRow{}, &versionRow{}, &runRow{}); err != nil {
		return nil, fmt.Errorf("workflow migration: %w", err)
	}
	return &GORMStore{db: db}, nil
}

func workflowRowFrom(w Workflow) workflowRow {
	return workflowRow{RefID: w.Ref.ID, OwnerID: w.OwnerID, Name: w.Name, State: string(w.State), CurrentVersion: w.CurrentVersion, Revision: w.Revision, CreatedAt: w.CreatedAt.UTC(), UpdatedAt: w.UpdatedAt.UTC(), DeletedAt: w.DeletedAt}
}
func workflowFromRow(r workflowRow) Workflow {
	return Workflow{Ref: resource.Ref{Kind: resource.Workflow, ID: r.RefID}, OwnerID: r.OwnerID, Name: r.Name, State: State(r.State), CurrentVersion: r.CurrentVersion, Revision: r.Revision, CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), DeletedAt: r.DeletedAt}
}
func versionRowFrom(v Version) versionRow {
	return versionRow{WorkflowID: v.Workflow.ID, Number: v.Number, State: string(v.State), Definition: append([]byte(nil), v.Definition...), Digest: v.Digest, CreatedAt: v.CreatedAt.UTC(), PublishedAt: v.PublishedAt}
}
func versionFromRow(r versionRow) Version {
	return Version{Workflow: resource.Ref{Kind: resource.Workflow, ID: r.WorkflowID}, Number: r.Number, State: VersionState(r.State), Definition: append([]byte(nil), r.Definition...), Digest: r.Digest, CreatedAt: r.CreatedAt.UTC(), PublishedAt: r.PublishedAt}
}
func runRowFrom(r Run) runRow {
	return runRow{RefID: r.Ref.ID, WorkflowID: r.Workflow.ID, Version: r.Version, OwnerID: r.OwnerID, State: string(r.State), SubjectKind: string(r.Execution.Subject.Kind), SubjectID: r.Execution.Subject.ID, TriggeredByKind: string(r.Execution.TriggeredBy.Kind), TriggeredByID: r.Execution.TriggeredBy.ID, Entry: string(r.Execution.Entry), TokenID: r.Execution.TokenID, SourceGrantID: r.Execution.SourceGrantID, OperationID: r.Execution.OperationID, Definition: append([]byte(nil), r.Definition...), Digest: r.Digest, ErrorCode: r.ErrorCode, ErrorMessage: r.ErrorMessage, Revision: r.Revision, CreatedAt: r.CreatedAt.UTC(), StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, UpdatedAt: r.UpdatedAt.UTC()}
}
func runFromRow(r runRow) Run {
	return Run{Ref: resource.Ref{Kind: resource.WorkflowRun, ID: r.RefID}, Workflow: resource.Ref{Kind: resource.Workflow, ID: r.WorkflowID}, Version: r.Version, OwnerID: r.OwnerID, State: RunState(r.State), Execution: authz.Execution{Subject: authz.Principal{Kind: authz.PrincipalKind(r.SubjectKind), ID: r.SubjectID}, TriggeredBy: authz.Principal{Kind: authz.PrincipalKind(r.TriggeredByKind), ID: r.TriggeredByID}, Entry: authz.Entry(r.Entry), TokenID: r.TokenID, SourceGrantID: r.SourceGrantID, OperationID: r.OperationID}, Definition: append([]byte(nil), r.Definition...), Digest: r.Digest, ErrorCode: r.ErrorCode, ErrorMessage: r.ErrorMessage, Revision: r.Revision, CreatedAt: r.CreatedAt.UTC(), StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, UpdatedAt: r.UpdatedAt.UTC()}
}

func (s *GORMStore) Create(ctx context.Context, w Workflow) error {
	if s == nil || s.db == nil || w.Validate() != nil {
		return ErrInvalidWorkflow
	}
	row := workflowRowFrom(w)
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		return err
	}
	return nil
}
func (s *GORMStore) Get(ctx context.Context, ref resource.Ref) (Workflow, error) {
	if ref.Kind != resource.Workflow || ref.Validate() != nil {
		return Workflow{}, ErrNotFound
	}
	var row workflowRow
	if err := s.db.WithContext(ctx).First(&row, "ref_id = ?", ref.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Workflow{}, ErrNotFound
		}
		return Workflow{}, err
	}
	w := workflowFromRow(row)
	if w.Validate() != nil {
		return Workflow{}, ErrInvalidWorkflow
	}
	return w, nil
}
func (s *GORMStore) List(ctx context.Context, owner uint64) ([]Workflow, error) {
	if owner == 0 {
		return nil, ErrInvalidWorkflow
	}
	var rows []workflowRow
	if err := s.db.WithContext(ctx).Where("owner_id = ? AND state <> ?", owner, string(StateDeleted)).Order("updated_at ASC, ref_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Workflow, 0, len(rows))
	for _, r := range rows {
		out = append(out, workflowFromRow(r))
	}
	return out, nil
}
func (s *GORMStore) Update(ctx context.Context, w Workflow, expected uint64) (Workflow, error) {
	if w.Validate() != nil || expected == 0 {
		return Workflow{}, ErrInvalidWorkflow
	}
	now := time.Now().UTC()
	q := s.db.WithContext(ctx).Model(&workflowRow{}).Where("ref_id = ? AND revision = ?", w.Ref.ID, expected).Updates(map[string]any{"name": w.Name, "state": string(w.State), "current_version": w.CurrentVersion, "revision": expected + 1, "updated_at": now, "deleted_at": w.DeletedAt})
	if q.Error != nil {
		return Workflow{}, q.Error
	}
	if q.RowsAffected != 1 {
		_, err := s.Get(ctx, w.Ref)
		if errors.Is(err, ErrNotFound) {
			return Workflow{}, ErrNotFound
		}
		return Workflow{}, ErrConflict
	}
	return s.Get(ctx, w.Ref)
}
func (s *GORMStore) Delete(ctx context.Context, ref resource.Ref, expected uint64) error {
	w, err := s.Get(ctx, ref)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if expected == 0 || w.Revision != expected {
		return ErrConflict
	}
	q := s.db.WithContext(ctx).Model(&workflowRow{}).Where("ref_id = ? AND revision = ?", ref.ID, expected).Updates(map[string]any{"state": string(StateDeleted), "deleted_at": now, "revision": expected + 1, "updated_at": now})
	if q.Error != nil {
		return q.Error
	}
	if q.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}

func (s *GORMStore) CreateVersion(ctx context.Context, v Version) error {
	if v.Validate() != nil {
		return ErrInvalidWorkflow
	}
	row := versionRowFrom(v)
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		return err
	}
	return nil
}
func (s *GORMStore) GetVersion(ctx context.Context, ref resource.Ref, n uint64) (Version, error) {
	if ref.Kind != resource.Workflow || ref.Validate() != nil || n == 0 {
		return Version{}, ErrVersionNotFound
	}
	var row versionRow
	if err := s.db.WithContext(ctx).Where("workflow_id = ? AND number = ?", ref.ID, n).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Version{}, ErrVersionNotFound
		}
		return Version{}, err
	}
	return versionFromRow(row), nil
}
func (s *GORMStore) ListVersions(ctx context.Context, ref resource.Ref) ([]Version, error) {
	if ref.Kind != resource.Workflow || ref.Validate() != nil {
		return nil, ErrVersionNotFound
	}
	var rows []versionRow
	if err := s.db.WithContext(ctx).Where("workflow_id = ?", ref.ID).Order("number ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Version, 0, len(rows))
	for _, r := range rows {
		out = append(out, versionFromRow(r))
	}
	return out, nil
}
func (s *GORMStore) PublishVersion(ctx context.Context, ref resource.Ref, n, expected uint64) (Workflow, error) {
	if ref.Kind != resource.Workflow || n == 0 || expected == 0 {
		return Workflow{}, ErrConflict
	}
	var out Workflow
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var w workflowRow
		if err := tx.First(&w, "ref_id = ?", ref.ID).Error; err != nil {
			return translate(err, ErrNotFound)
		}
		if w.Revision != expected || w.State == string(StateDeleted) {
			return ErrConflict
		}
		var v versionRow
		if err := tx.Where("workflow_id = ? AND number = ?", ref.ID, n).First(&v).Error; err != nil {
			return translate(err, ErrVersionNotFound)
		}
		if v.State == string(VersionPublished) {
			out = workflowFromRow(w)
			return nil
		}
		now := time.Now().UTC()
		if err := tx.Model(&versionRow{}).Where("workflow_id = ? AND number = ? AND state = ?", ref.ID, n, string(VersionDraft)).Updates(map[string]any{"state": string(VersionPublished), "published_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Model(&workflowRow{}).Where("ref_id = ? AND revision = ?", ref.ID, expected).Updates(map[string]any{"state": string(StateActive), "current_version": n, "revision": expected + 1, "updated_at": now}).Error; err != nil {
			return err
		}
		w.Revision++
		w.CurrentVersion = n
		w.State = string(StateActive)
		w.UpdatedAt = now
		out = workflowFromRow(w)
		return nil
	})
	return out, err
}

func (s *GORMStore) CreateRun(ctx context.Context, r Run) error {
	if r.Validate() != nil {
		return ErrInvalidWorkflow
	}
	row := runRowFrom(r)
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		return err
	}
	return nil
}
func (s *GORMStore) GetRun(ctx context.Context, ref resource.Ref) (Run, error) {
	if ref.Kind != resource.WorkflowRun || ref.Validate() != nil {
		return Run{}, ErrRunNotFound
	}
	var row runRow
	if err := s.db.WithContext(ctx).First(&row, "ref_id = ?", ref.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Run{}, ErrRunNotFound
		}
		return Run{}, err
	}
	return runFromRow(row), nil
}
func (s *GORMStore) ListRuns(ctx context.Context, ref resource.Ref) ([]Run, error) {
	if ref.Kind != resource.Workflow || ref.Validate() != nil {
		return nil, ErrNotFound
	}
	var rows []runRow
	if err := s.db.WithContext(ctx).Where("workflow_id = ?", ref.ID).Order("created_at DESC, ref_id DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Run, 0, len(rows))
	for _, r := range rows {
		out = append(out, runFromRow(r))
	}
	return out, nil
}
func (s *GORMStore) UpdateRun(ctx context.Context, r Run, expected uint64) (Run, error) {
	if r.Validate() != nil || expected == 0 {
		return Run{}, ErrInvalidWorkflow
	}
	now := time.Now().UTC()
	q := s.db.WithContext(ctx).Model(&runRow{}).Where("ref_id = ? AND revision = ?", r.Ref.ID, expected).Updates(map[string]any{"state": string(r.State), "error_code": r.ErrorCode, "error_message": r.ErrorMessage, "revision": expected + 1, "started_at": r.StartedAt, "finished_at": r.FinishedAt, "updated_at": now})
	if q.Error != nil {
		return Run{}, q.Error
	}
	if q.RowsAffected != 1 {
		return Run{}, ErrConflict
	}
	return s.GetRun(ctx, r.Ref)
}
func translate(err, notFound error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return notFound
	}
	return err
}

// Keep encoding/json referenced here for compatibility with older generated
// migrations that inspect the execution payload type.
var _ = json.Valid
