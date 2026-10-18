// Package credential defines metadata, encrypted storage and purpose-bound
// secret resolution. It does not store provider keys in business objects.
package credential

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/resource"
)

// Type identifies an authentication schema, not merely a cloud vendor name.
// Adapters must register distinct types for incompatible authentication formats.
type Type string
type Purpose string

const (
	DNSManage         Purpose = "dns.manage"
	DNSChallenge      Purpose = "dns.challenge"
	CertificateIssue  Purpose = "certificate.issue"
	CertificateDeploy Purpose = "certificate.deploy"
	NotificationSend  Purpose = "notification.send"
)

// Ref is stored as credential_ref in business objects. Version zero resolves
// the current enabled version once per use; a nonzero version is pinned.
type Ref struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

func (r Ref) Resource() resource.Ref { return resource.Ref{Kind: resource.Credential, ID: r.ID} }

// Binding restricts both the consuming workflow/binding and the actual target.
// A purpose alone must never authorize every target accessible to a provider key.
type Binding struct {
	Purpose  Purpose      `json:"purpose"`
	Consumer resource.Ref `json:"consumer"`
	Target   resource.Ref `json:"target"`
}

// Metadata is safe for authorized metadata APIs. View does not imply use,
// reveal, export or rotate. Bindings themselves require resource filtering.
type Metadata struct {
	Resource       resource.Metadata `json:"resource"`
	Name           string            `json:"name"`
	Type           Type              `json:"type"`
	CurrentVersion uint64            `json:"current_version"`
	Bindings       []Binding         `json:"bindings"`
}

type UseRequest struct {
	Execution        authz.Execution `json:"execution"`
	Credential       Ref             `json:"credential_ref"`
	ExpectedType     Type            `json:"expected_type"`
	Binding          Binding         `json:"binding"`
	Action           authz.Action    `json:"action"`
	DNS              []authz.DNSName `json:"dns,omitempty"`
	CertificateNames []string        `json:"certificate_names,omitempty"`
}

// Validate checks structure only. The resolver still has to load current
// policy, authoritative resource facts and credential bindings from storage.
func (r UseRequest) Validate() error {
	request := authz.Request{Execution: r.Execution, Action: r.Action, Resource: r.Binding.Target, DNS: r.DNS, CertificateNames: r.CertificateNames}
	if request.Validate() != nil || r.Credential.Resource().Validate() != nil || r.Binding.Consumer.Validate() != nil || strings.TrimSpace(string(r.ExpectedType)) == "" {
		return errors.New("invalid credential use request")
	}
	switch r.Binding.Purpose {
	case DNSManage, DNSChallenge, CertificateIssue, CertificateDeploy, NotificationSend:
		return nil
	default:
		return errors.New("invalid credential purpose")
	}
}

type Resolved struct {
	Version uint64  `json:"version"`
	Type    Type    `json:"type"`
	Secret  *Secret `json:"-"`
}

// Resolver rechecks current authorization on consumer, target/action and
// credential/use, then checks type, purpose, enabled state and version. It must
// invoke fn only after all checks succeed and destroy the secret on every exit,
// including panic. Callers must not retain secret bytes or put them in errors.
// A disabled/deleted credential or revoked version fails closed. Normal use
// cannot implement reveal/export; those need separate explicit permissions.
type Resolver interface {
	WithSecret(context.Context, UseRequest, func(context.Context, Resolved) error) error
}

// EncryptedSecret is a storage envelope, never a metadata/API response. KeyID
// selects a server-managed key that must be recoverable separately from the DB.
type EncryptedSecret struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Protector requires authenticated encryption bound to credential identity and
// version as associated data. Open must reject tampering and envelope swapping.
// Implementations must use fresh nonces and must not persist plaintext keys.
type Protector interface {
	Seal(ctx context.Context, credential resource.Ref, version uint64, secret *Secret) (EncryptedSecret, error)
	Open(ctx context.Context, credential resource.Ref, version uint64, encrypted EncryptedSecret) (*Secret, error)
}

// Secret prevents accidental serialization and formatting. Bytes is an explicit
// escape hatch for provider adapters, scoped to the WithSecret callback. This
// cannot erase copies made by a provider SDK or make arbitrary logging safe.
// A Secret is callback-local and must not be accessed concurrently with Destroy.
type Secret struct{ data []byte }

func NewSecret(data []byte) *Secret { return &Secret{data: append([]byte(nil), data...)} }
func (s *Secret) Bytes() []byte     { return s.data }
func (s *Secret) Destroy() {
	if s == nil {
		return
	}
	clear(s.data)
	s.data = nil
}
func (Secret) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte("[REDACTED]")) }
func (Secret) MarshalJSON() ([]byte, error)   { return []byte(`"[REDACTED]"`), nil }
func (Secret) MarshalText() ([]byte, error)   { return []byte("[REDACTED]"), nil }
func (Secret) LogValue() slog.Value           { return slog.StringValue("[REDACTED]") }
