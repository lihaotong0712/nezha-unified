// Package resource defines stable references shared by the unified modules.
// It does not own business records or change existing Nezha IDs.
package resource

import (
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Kind string

const (
	User             Kind = "user"
	Server           Kind = "server"
	APIToken         Kind = "api_token"
	Domain           Kind = "domain"
	DNSZone          Kind = "dns_zone"
	DNSRecord        Kind = "dns_record"
	DDNSBinding      Kind = "ddns_binding"
	Certificate      Kind = "certificate"
	Workflow         Kind = "workflow"
	WorkflowRun      Kind = "workflow_run"
	Credential       Kind = "credential"
	DeploymentTarget Kind = "deployment_target"
)

// Ref uses a string ID so uint64 Nezha IDs survive JavaScript round trips and
// opaque certificate-store IDs retain their exact value. Provider IDs are not
// platform resource IDs; business modules must resolve the mapping server-side.
type Ref struct {
	Kind Kind   `json:"kind"`
	ID   string `json:"id"`
}

var ErrInvalidRef = errors.New("invalid resource reference")

func (r Ref) Validate() error {
	switch r.Kind {
	case User, Server, APIToken:
		id, err := strconv.ParseUint(r.ID, 10, 64)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != r.ID {
			return ErrInvalidRef
		}
	case Domain, DNSZone, DNSRecord, DDNSBinding, Certificate, Workflow, WorkflowRun, Credential, DeploymentTarget:
		return ValidateOpaqueID(r.ID)
	default:
		return ErrInvalidRef
	}
	return nil
}

// ValidateOpaqueID checks a local registry ID without normalizing its value.
// Invalid UTF-8 is rejected because JSON would replace bytes and change identity.
func ValidateOpaqueID(id string) error {
	if id == "" || len(id) > 255 || !utf8.ValidString(id) || strings.ContainsAny(id, ":/\\") || strings.ContainsFunc(id, func(c rune) bool {
		return unicode.IsSpace(c) || unicode.IsControl(c)
	}) {
		return ErrInvalidRef
	}
	return nil
}

// Native converts a Nezha primary key without applying the UI's idcodec.
func Native(kind Kind, id uint64) (Ref, error) {
	if kind != User && kind != Server && kind != APIToken {
		return Ref{}, ErrInvalidRef
	}
	r := Ref{Kind: kind, ID: strconv.FormatUint(id, 10)}
	return r, r.Validate()
}

type State string

const (
	Pending  State = "pending"
	Active   State = "active"
	Disabled State = "disabled"
	Deleted  State = "deleted"
)

// Metadata is the cross-module projection of the authoritative resource
// registry. OwnerID is an existing Nezha user ID; zero never means administrator.
// Business stores must not maintain a second independently editable owner.
type Metadata struct {
	Ref       Ref        `json:"ref"`
	OwnerID   uint64     `json:"owner_id,string"`
	Revision  uint64     `json:"revision"`
	State     State      `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// Executable is a lifecycle guard, not an authorization decision.
func (m Metadata) Executable() bool {
	return m.Ref.Validate() == nil && m.OwnerID != 0 && m.Revision != 0 && m.State == Active && m.DeletedAt == nil
}
