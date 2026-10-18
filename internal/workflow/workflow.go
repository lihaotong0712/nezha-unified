// Package workflow provides the persistent certificate workflow boundary.
// Workflow definitions are versioned immutable JSON documents; runs always
// retain the exact published definition they started with.
package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/resource"
)

const MaxDefinitionBytes = 1 << 20

type State string

const (
	StateDraft    State = "draft"
	StateActive   State = "active"
	StateDisabled State = "disabled"
	StateDeleted  State = "deleted"
)

type VersionState string

const (
	VersionDraft     VersionState = "draft"
	VersionPublished VersionState = "published"
)

type RunState string

const (
	RunPending   RunState = "pending"
	RunRunning   RunState = "running"
	RunSucceeded RunState = "succeeded"
	RunFailed    RunState = "failed"
	RunCanceled  RunState = "canceled"
)

var (
	ErrInvalidWorkflow      = errors.New("invalid workflow")
	ErrInvalidDefinition    = errors.New("invalid workflow definition")
	ErrNotFound             = errors.New("workflow not found")
	ErrVersionNotFound      = errors.New("workflow version not found")
	ErrRunNotFound          = errors.New("workflow run not found")
	ErrConflict             = errors.New("workflow conflict")
	ErrDisabled             = errors.New("workflow is disabled")
	ErrNoPublishedVersion   = errors.New("workflow has no published version")
	ErrInvalidRunTransition = errors.New("invalid workflow run transition")
)

type Workflow struct {
	Ref            resource.Ref `json:"ref"`
	OwnerID        uint64       `json:"owner_id,string"`
	Name           string       `json:"name"`
	State          State        `json:"state"`
	CurrentVersion uint64       `json:"current_version"`
	Revision       uint64       `json:"revision"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	DeletedAt      *time.Time   `json:"deleted_at,omitempty"`
}

type Version struct {
	Workflow    resource.Ref    `json:"workflow"`
	Number      uint64          `json:"number"`
	State       VersionState    `json:"state"`
	Definition  json.RawMessage `json:"definition"`
	Digest      string          `json:"digest"`
	CreatedAt   time.Time       `json:"created_at"`
	PublishedAt *time.Time      `json:"published_at,omitempty"`
}

type Run struct {
	Ref          resource.Ref    `json:"ref"`
	Workflow     resource.Ref    `json:"workflow"`
	Version      uint64          `json:"version"`
	OwnerID      uint64          `json:"owner_id,string"`
	State        RunState        `json:"state"`
	Execution    authz.Execution `json:"execution"`
	Definition   json.RawMessage `json:"definition"`
	Digest       string          `json:"digest"`
	ErrorCode    string          `json:"error_code,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
	Revision     uint64          `json:"revision"`
	CreatedAt    time.Time       `json:"created_at"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	FinishedAt   *time.Time      `json:"finished_at,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type Store interface {
	Create(context.Context, Workflow) error
	Get(context.Context, resource.Ref) (Workflow, error)
	List(context.Context, uint64) ([]Workflow, error)
	Update(context.Context, Workflow, uint64) (Workflow, error)
	Delete(context.Context, resource.Ref, uint64) error
	CreateVersion(context.Context, Version) error
	GetVersion(context.Context, resource.Ref, uint64) (Version, error)
	ListVersions(context.Context, resource.Ref) ([]Version, error)
	PublishVersion(context.Context, resource.Ref, uint64, uint64) (Workflow, error)
	CreateRun(context.Context, Run) error
	GetRun(context.Context, resource.Ref) (Run, error)
	ListRuns(context.Context, resource.Ref) ([]Run, error)
	UpdateRun(context.Context, Run, uint64) (Run, error)
}

type CreateRequest struct {
	Execution  authz.Execution
	OwnerID    uint64
	Name       string
	Definition json.RawMessage
}

type UpdateRequest struct {
	Name       string
	Definition json.RawMessage
}

type StartRunRequest struct {
	Execution authz.Execution
	Workflow  resource.Ref
}

func ValidateDefinition(definition []byte) (json.RawMessage, string, error) {
	if len(definition) == 0 || len(definition) > MaxDefinitionBytes || !json.Valid(definition) {
		return nil, "", ErrInvalidDefinition
	}
	var value any
	if err := json.Unmarshal(definition, &value); err != nil {
		return nil, "", ErrInvalidDefinition
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, "", ErrInvalidDefinition
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return nil, "", ErrInvalidDefinition
	}
	sum := sha256.Sum256(normalized)
	return normalized, hex.EncodeToString(sum[:]), nil
}

func (w Workflow) Validate() error {
	if w.Ref.Kind != resource.Workflow || w.Ref.Validate() != nil || w.OwnerID == 0 || strings.TrimSpace(w.Name) == "" || w.Revision == 0 {
		return ErrInvalidWorkflow
	}
	switch w.State {
	case StateDraft, StateActive, StateDisabled, StateDeleted:
	default:
		return ErrInvalidWorkflow
	}
	if w.State == StateDeleted && w.DeletedAt == nil {
		return ErrInvalidWorkflow
	}
	return nil
}

func (v Version) Validate() error {
	if v.Workflow.Kind != resource.Workflow || v.Workflow.Validate() != nil || v.Number == 0 || v.Digest == "" {
		return ErrInvalidWorkflow
	}
	if v.State != VersionDraft && v.State != VersionPublished {
		return ErrInvalidWorkflow
	}
	normalized, digest, err := ValidateDefinition(v.Definition)
	if err != nil || digest != v.Digest || string(normalized) != string(v.Definition) {
		return ErrInvalidDefinition
	}
	if v.State == VersionPublished && v.PublishedAt == nil {
		return ErrInvalidWorkflow
	}
	return nil
}

func (r Run) Validate() error {
	if r.Ref.Kind != resource.WorkflowRun || r.Ref.Validate() != nil || r.Workflow.Kind != resource.Workflow || r.Workflow.Validate() != nil || r.Version == 0 || r.OwnerID == 0 || r.Revision == 0 || r.Execution.Validate() != nil || r.Digest == "" {
		return ErrInvalidWorkflow
	}
	switch r.State {
	case RunPending, RunRunning, RunSucceeded, RunFailed, RunCanceled:
	default:
		return ErrInvalidWorkflow
	}
	normalized, digest, err := ValidateDefinition(r.Definition)
	if err != nil || digest != r.Digest || string(normalized) != string(r.Definition) {
		return ErrInvalidDefinition
	}
	return nil
}

func nextRunState(from, to RunState) bool {
	switch from {
	case RunPending:
		return to == RunRunning || to == RunCanceled
	case RunRunning:
		return to == RunSucceeded || to == RunFailed || to == RunCanceled
	default:
		return false
	}
}

func newID(prefix string, now time.Time) string { return fmt.Sprintf("%s%d", prefix, now.UnixNano()) }
