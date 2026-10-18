// Package audit defines bounded, secret-free records for unified operations.
package audit

import (
	"context"
	"time"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
)

type Outcome string

const (
	Requested Outcome = "requested"
	Succeeded Outcome = "succeeded"
	Denied    Outcome = "denied"
	Failed    Outcome = "failed"
	Canceled  Outcome = "canceled"
)

// Event has no arbitrary payload/message field: provider bodies, URLs, keys,
// scripts and certificate private keys must not enter the shared audit stream.
// ID identifies a single event for idempotent append; OperationID (in Execution)
// correlates multiple attempts and outcomes for the same logical operation.
type Event struct {
	ID                string           `json:"id"`
	Time              time.Time        `json:"time"`
	Execution         authz.Execution  `json:"execution"`
	Action            authz.Action     `json:"action"`
	Resource          resource.Ref     `json:"resource"`
	Outcome           Outcome          `json:"outcome"`
	Code              platformerr.Code `json:"code,omitempty"`
	PolicyVersion     string           `json:"policy_version,omitempty"`
	GrantIDs          []string         `json:"grant_ids,omitempty"`
	Credential        *resource.Ref    `json:"credential,omitempty"`
	CredentialVersion uint64           `json:"credential_version,omitempty"`
	ResourceRevision  uint64           `json:"resource_revision,omitempty"`
}

// Recorder must durably append or return an error, and deduplicate by event ID.
// Sensitive operations must record their intent before exposing a secret or
// sending a side effect. Audit failures cannot silently become success.
type Recorder interface {
	Record(context.Context, Event) error
}
