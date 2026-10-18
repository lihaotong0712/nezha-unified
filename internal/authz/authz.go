// Package authz defines the authorization boundary used by every new execution
// entry point. Identity and policy must be loaded from trusted server state.
package authz

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
)

type PrincipalKind string

const (
	UserPrincipal    PrincipalKind = "user"
	ServicePrincipal PrincipalKind = "service"
	AgentPrincipal   PrincipalKind = "agent"
	DevicePrincipal  PrincipalKind = "device"
)

// Principal is an identity reference, not a caller-supplied role or permission.
// User IDs and Agent IDs are the existing Nezha user and server primary keys.
type Principal struct {
	Kind PrincipalKind `json:"kind"`
	ID   string        `json:"id"`
}

func (p Principal) Validate() error {
	switch p.Kind {
	case UserPrincipal:
		return (resource.Ref{Kind: resource.User, ID: p.ID}).Validate()
	case AgentPrincipal:
		return (resource.Ref{Kind: resource.Server, ID: p.ID}).Validate()
	case ServicePrincipal, DevicePrincipal:
		return resource.ValidateOpaqueID(p.ID)
	default:
		return errors.New("invalid principal")
	}
}

type Entry string

const (
	Session  Entry = "session"
	PAT      Entry = "pat"
	Schedule Entry = "schedule"
	Workflow Entry = "workflow"
	Retry    Entry = "retry"
	Recovery Entry = "recovery"
	Agent    Entry = "agent"
	Device   Entry = "device"
)

// Execution is persisted with jobs. Subject is the effective identity;
// TriggeredBy records who initiated this attempt. TokenID and SourceGrantID
// remain attached to derived work, so scheduling cannot widen its privileges.
// OperationID identifies one logical operation and is retained across retries.
type Execution struct {
	Subject       Principal `json:"subject"`
	TriggeredBy   Principal `json:"triggered_by"`
	Entry         Entry     `json:"entry"`
	TokenID       uint64    `json:"token_id,string,omitempty"`
	SourceGrantID string    `json:"source_grant_id,omitempty"`
	OperationID   string    `json:"operation_id"`
}

func (e Execution) Validate() error {
	if e.Subject.Validate() != nil || e.TriggeredBy.Validate() != nil || strings.TrimSpace(e.OperationID) == "" {
		return errors.New("invalid execution identity")
	}
	if e.TokenID != 0 && e.Subject.Kind != UserPrincipal {
		return errors.New("token restrictions require a user subject")
	}
	switch e.Entry {
	case Session, PAT:
		if e.Subject.Kind != UserPrincipal || e.TriggeredBy != e.Subject || (e.Entry == PAT && e.TokenID == 0) || (e.Entry == Session && e.TokenID != 0) {
			return errors.New("invalid interactive execution")
		}
	case Schedule, Workflow, Retry, Recovery:
		if e.Subject.Kind != UserPrincipal && e.Subject.Kind != ServicePrincipal {
			return errors.New("invalid background execution")
		}
	case Agent:
		if e.Subject.Kind != AgentPrincipal || e.TokenID != 0 {
			return errors.New("invalid agent execution")
		}
	case Device:
		if e.Subject.Kind != DevicePrincipal || e.TokenID != 0 {
			return errors.New("invalid device execution")
		}
	default:
		return errors.New("invalid execution entry")
	}
	return nil
}

type Action string

const (
	View     Action = "view"
	Edit     Action = "edit"
	Execute  Action = "execute"
	Export   Action = "export"
	Download Action = "download"
	Delete   Action = "delete"
	Use      Action = "use"
	Reveal   Action = "reveal"
	Rotate   Action = "rotate"
	Grant    Action = "grant"
)

type Request struct {
	Execution Execution    `json:"execution"`
	Action    Action       `json:"action"`
	Resource  resource.Ref `json:"resource"`
	// DNS contains the actual old and proposed records on rename/update, or
	// the proposed record on create. CertificateNames contains all resolved
	// SANs. These are server-resolved facts, never trusted browser labels.
	DNS              []DNSName `json:"dns,omitempty"`
	CertificateNames []string  `json:"certificate_names,omitempty"`
}

// DNSName binds a name to a managed zone and record type. The authorizer must
// resolve the zone/account and normalize IDNA, case and trailing dots before
// matching DNS label boundaries; wildcard and root permissions are separate.
type DNSName struct {
	Zone       resource.Ref `json:"zone"`
	Name       string       `json:"name"`
	RecordType string       `json:"record_type"`
}

func (r Request) Validate() error {
	if r.Execution.Validate() != nil || r.Resource.Validate() != nil || !validAction(r.Action) {
		return errors.New("invalid authorization request")
	}
	for _, name := range r.DNS {
		if name.Zone.Kind != resource.DNSZone || name.Zone.Validate() != nil || strings.TrimSpace(name.Name) == "" || strings.TrimSpace(name.RecordType) == "" {
			return errors.New("invalid DNS scope")
		}
	}
	for _, name := range r.CertificateNames {
		if strings.TrimSpace(name) == "" {
			return errors.New("invalid certificate scope")
		}
	}
	return nil
}

type Decision struct {
	Allowed       bool     `json:"allowed"`
	PolicyVersion string   `json:"policy_version"`
	GrantIDs      []string `json:"grant_ids,omitempty"`
}

// Authorizer evaluates current identity permissions intersected with resource
// grants, token restrictions and target restrictions. Administrators do not
// bypass token restrictions. No cached Decision is authority for a later side
// effect. An unavailable policy store must return an error, never allow.
type Authorizer interface {
	Authorize(context.Context, Request) (Decision, error)
}

// Check enforces fail-closed handling, including zero-value decisions.
func Check(ctx context.Context, a Authorizer, request Request) (Decision, error) {
	op := request.Execution.OperationID
	if err := ctx.Err(); err != nil {
		return Decision{}, platformerr.From(err, op)
	}
	if request.Validate() != nil {
		return Decision{}, platformerr.New(platformerr.InvalidArgument, op, nil)
	}
	if a == nil {
		return Decision{}, platformerr.New(platformerr.Unavailable, op, nil)
	}
	decision, err := a.Authorize(ctx, request)
	if err != nil {
		return Decision{}, platformerr.From(err, op)
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, platformerr.From(err, op)
	}
	if !decision.Allowed {
		return Decision{}, platformerr.New(platformerr.Forbidden, op, nil)
	}
	if strings.TrimSpace(decision.PolicyVersion) == "" {
		return Decision{}, platformerr.New(platformerr.Unavailable, op, nil)
	}
	return decision, nil
}

func validAction(action Action) bool {
	switch action {
	case View, Edit, Execute, Export, Download, Delete, Use, Reveal, Rotate, Grant:
		return true
	}
	return false
}

// User constructs a principal from a trusted Nezha user primary key.
func User(id uint64) Principal {
	return Principal{Kind: UserPrincipal, ID: strconv.FormatUint(id, 10)}
}
