package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/gorm"
)

var (
	// ErrPolicyConflict is returned when a grant ID is reused with different data.
	ErrPolicyConflict = errors.New("authorization policy conflict")
	// ErrPolicyNotFound is returned when a requested grant does not exist.
	ErrPolicyNotFound = gorm.ErrRecordNotFound
)

// DNSScope is a persisted name boundary. Pattern is either an exact normalized
// name or a leading "*." subtree pattern; a suffix string is never treated as a
// match without a DNS label boundary.
type DNSScope struct {
	Zone       resource.Ref `json:"zone"`
	Pattern    string       `json:"pattern"`
	RecordType string       `json:"record_type"`
}

// PolicyGrant is the editable policy projection. It contains no user role or
// password data; identity and PAT state continue to come from existing tables.
type PolicyGrant struct {
	ID               string
	Principal        Principal
	Resource         resource.Ref
	Actions          []Action
	ServerIDs        []uint64
	DNS              []DNSScope
	CertificateNames []string
	PolicyVersion    string
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PolicyStore stores grants used by the authorizer.
type PolicyStore interface {
	PutGrant(context.Context, PolicyGrant) error
	GetGrant(context.Context, string) (PolicyGrant, error)
	DeleteGrant(context.Context, string) error
	ListGrants(context.Context, Principal) ([]PolicyGrant, error)
}

type policyGrantRow struct {
	ID              string    `gorm:"primaryKey;type:varchar(255)"`
	PrincipalKind   string    `gorm:"not null;index:idx_policy_subject"`
	PrincipalID     string    `gorm:"not null;index:idx_policy_subject"`
	ResourceKind    string    `gorm:"not null;index:idx_policy_resource"`
	ResourceID      string    `gorm:"not null;index:idx_policy_resource"`
	ActionsJSON     string    `gorm:"not null;type:text"`
	ServerIDsJSON   string    `gorm:"type:text"`
	DNSJSON         string    `gorm:"type:text"`
	CertificateJSON string    `gorm:"type:text"`
	PolicyVersion   string    `gorm:"not null;type:varchar(255)"`
	Enabled         bool      `gorm:"not null;index"`
	CreatedAt       time.Time `gorm:"not null"`
	UpdatedAt       time.Time `gorm:"not null"`
}

func (policyGrantRow) TableName() string { return "platform_policy_grants" }

// GORMAuthorizer persists grants and evaluates each request against current
// grants and the existing api_tokens table. It intentionally has no admin
// short-circuit: a PAT's scope and server whitelist always remain effective.
type GORMAuthorizer struct{ db *gorm.DB }

func NewGORMAuthorizer(db *gorm.DB) (*GORMAuthorizer, error) {
	if db == nil {
		return nil, errors.New("authz: nil database")
	}
	if err := db.AutoMigrate(&policyGrantRow{}); err != nil {
		return nil, fmt.Errorf("authz policy migration: %w", err)
	}
	return &GORMAuthorizer{db: db}, nil
}

// NewPolicyStore is an alias for callers that only need grant persistence.
func NewPolicyStore(db *gorm.DB) (*GORMAuthorizer, error) { return NewGORMAuthorizer(db) }

func validateGrant(g PolicyGrant) error {
	if err := resource.ValidateOpaqueID(g.ID); err != nil || g.Principal.Validate() != nil {
		return errors.New("invalid policy grant")
	}
	if g.Resource.ID == "*" {
		if !validResourceKind(g.Resource.Kind) {
			return errors.New("invalid policy resource")
		}
	} else if g.Resource.Validate() != nil {
		return errors.New("invalid policy resource")
	}
	if strings.TrimSpace(g.PolicyVersion) == "" {
		return errors.New("invalid policy version")
	}
	if len(g.Actions) == 0 {
		return errors.New("policy grant has no actions")
	}
	seen := make(map[Action]bool, len(g.Actions))
	for _, action := range g.Actions {
		if !validAction(action) || seen[action] {
			return errors.New("invalid policy action")
		}
		seen[action] = true
	}
	for _, id := range g.ServerIDs {
		if id == 0 {
			return errors.New("invalid policy server scope")
		}
	}
	for _, name := range g.DNS {
		if name.Zone.Kind != resource.DNSZone || name.Zone.Validate() != nil || strings.TrimSpace(name.Pattern) == "" || strings.TrimSpace(name.RecordType) == "" {
			return errors.New("invalid policy DNS scope")
		}
	}
	for _, name := range g.CertificateNames {
		if strings.TrimSpace(name) == "" {
			return errors.New("invalid policy certificate scope")
		}
	}
	return nil
}

func rowFromGrant(g PolicyGrant) (policyGrantRow, error) {
	actions, err := json.Marshal(g.Actions)
	if err != nil {
		return policyGrantRow{}, err
	}
	servers, err := json.Marshal(g.ServerIDs)
	if err != nil {
		return policyGrantRow{}, err
	}
	dns, err := json.Marshal(g.DNS)
	if err != nil {
		return policyGrantRow{}, err
	}
	certs, err := json.Marshal(g.CertificateNames)
	if err != nil {
		return policyGrantRow{}, err
	}
	now := time.Now().UTC()
	created := g.CreatedAt
	if created.IsZero() {
		created = now
	}
	updated := g.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	return policyGrantRow{ID: g.ID, PrincipalKind: string(g.Principal.Kind), PrincipalID: g.Principal.ID, ResourceKind: string(g.Resource.Kind), ResourceID: g.Resource.ID, ActionsJSON: string(actions), ServerIDsJSON: string(servers), DNSJSON: string(dns), CertificateJSON: string(certs), PolicyVersion: g.PolicyVersion, Enabled: g.Enabled, CreatedAt: created.UTC(), UpdatedAt: updated.UTC()}, nil
}

func grantFromRow(r policyGrantRow) (PolicyGrant, error) {
	g := PolicyGrant{ID: r.ID, Principal: Principal{Kind: PrincipalKind(r.PrincipalKind), ID: r.PrincipalID}, Resource: resource.Ref{Kind: resource.Kind(r.ResourceKind), ID: r.ResourceID}, PolicyVersion: r.PolicyVersion, Enabled: r.Enabled, CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC()}
	if err := json.Unmarshal([]byte(r.ActionsJSON), &g.Actions); err != nil {
		return PolicyGrant{}, err
	}
	if r.ServerIDsJSON != "" {
		if err := json.Unmarshal([]byte(r.ServerIDsJSON), &g.ServerIDs); err != nil {
			return PolicyGrant{}, err
		}
	}
	if r.DNSJSON != "" {
		if err := json.Unmarshal([]byte(r.DNSJSON), &g.DNS); err != nil {
			return PolicyGrant{}, err
		}
	}
	if r.CertificateJSON != "" {
		if err := json.Unmarshal([]byte(r.CertificateJSON), &g.CertificateNames); err != nil {
			return PolicyGrant{}, err
		}
	}
	return g, nil
}

func (a *GORMAuthorizer) PutGrant(ctx context.Context, g PolicyGrant) error {
	if err := validateGrant(g); err != nil {
		return err
	}
	row, err := rowFromGrant(g)
	if err != nil {
		return err
	}
	var existing policyGrantRow
	findErr := a.db.WithContext(ctx).First(&existing, "id = ?", g.ID).Error
	if findErr == nil {
		if existing.PrincipalKind == row.PrincipalKind && existing.PrincipalID == row.PrincipalID && existing.ResourceKind == row.ResourceKind && existing.ResourceID == row.ResourceID && existing.ActionsJSON == row.ActionsJSON && existing.ServerIDsJSON == row.ServerIDsJSON && existing.DNSJSON == row.DNSJSON && existing.CertificateJSON == row.CertificateJSON && existing.PolicyVersion == row.PolicyVersion && existing.Enabled == row.Enabled {
			return nil
		}
		return ErrPolicyConflict
	}
	if !errors.Is(findErr, gorm.ErrRecordNotFound) {
		return findErr
	}
	if err := a.db.WithContext(ctx).Create(&row).Error; err != nil {
		var check policyGrantRow
		if a.db.WithContext(ctx).First(&check, "id = ?", g.ID).Error == nil {
			return ErrPolicyConflict
		}
		return err
	}
	return nil
}

func (a *GORMAuthorizer) GetGrant(ctx context.Context, id string) (PolicyGrant, error) {
	if resource.ValidateOpaqueID(id) != nil {
		return PolicyGrant{}, ErrPolicyNotFound
	}
	var row policyGrantRow
	if err := a.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		return PolicyGrant{}, err
	}
	return grantFromRow(row)
}

func (a *GORMAuthorizer) DeleteGrant(ctx context.Context, id string) error {
	if resource.ValidateOpaqueID(id) != nil {
		return ErrPolicyNotFound
	}
	q := a.db.WithContext(ctx).Delete(&policyGrantRow{}, "id = ?", id)
	if q.Error != nil {
		return q.Error
	}
	if q.RowsAffected == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

func (a *GORMAuthorizer) ListGrants(ctx context.Context, p Principal) ([]PolicyGrant, error) {
	if p.Validate() != nil {
		return nil, errors.New("invalid principal")
	}
	var rows []policyGrantRow
	if err := a.db.WithContext(ctx).Where("principal_kind = ? AND principal_id = ? AND enabled = ?", string(p.Kind), p.ID, true).Order("id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]PolicyGrant, 0, len(rows))
	for _, row := range rows {
		grant, err := grantFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, nil
}

// Authorize evaluates current policy and then intersects it with the current
// PAT row, including scope and server whitelist. A missing or malformed PAT is
// a denial, never an unlimited token.
func (a *GORMAuthorizer) Authorize(ctx context.Context, req Request) (Decision, error) {
	if err := req.Validate(); err != nil {
		return Decision{}, err
	}
	grants, err := a.ListGrants(ctx, req.Execution.Subject)
	if err != nil {
		return Decision{}, err
	}
	var pat *patRecord
	if req.Execution.TokenID != 0 {
		pat, err = a.loadPAT(ctx, req.Execution.TokenID, req.Execution.Subject)
		if err != nil {
			return Decision{Allowed: false}, nil
		}
		if !patAllowsScope(pat.ScopesCSV, req.Action, req.Resource.Kind) || !patAllowsResource(pat.ServersCSV, req.Resource) {
			return Decision{Allowed: false}, nil
		}
	}
	matching := make([]PolicyGrant, 0, len(grants))
	for _, grant := range grants {
		if req.Execution.SourceGrantID != "" && grant.ID != req.Execution.SourceGrantID {
			continue
		}
		if !grantResourceMatches(grant.Resource, req.Resource) || !containsAction(grant.Actions, req.Action) || !grantTargetsRequest(grant, req) {
			continue
		}
		if pat != nil && !patIntersectsGrant(pat.ServersCSV, grant, req.Resource) {
			continue
		}
		matching = append(matching, grant)
	}
	if len(matching) == 0 {
		return Decision{Allowed: false}, nil
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].ID < matching[j].ID })
	grantIDs := make([]string, len(matching))
	versions := make([]string, len(matching))
	for i, grant := range matching {
		grantIDs[i], versions[i] = grant.ID, grant.PolicyVersion
	}
	sort.Strings(versions)
	return Decision{Allowed: true, PolicyVersion: strings.Join(uniqueStrings(versions), ","), GrantIDs: grantIDs}, nil
}

// Filter evaluates each resource independently and is useful for authorized
// list endpoints. It never turns a policy-store error into an allowed result.
func (a *GORMAuthorizer) Filter(ctx context.Context, execution Execution, action Action, refs []resource.Ref) ([]resource.Ref, error) {
	out := make([]resource.Ref, 0, len(refs))
	for _, ref := range refs {
		decision, err := a.Authorize(ctx, Request{Execution: execution, Action: action, Resource: ref})
		if err != nil {
			return nil, err
		}
		if decision.Allowed {
			out = append(out, ref)
		}
	}
	return out, nil
}

type patRecord struct {
	ID         uint64     `gorm:"column:id;primaryKey"`
	UserID     uint64     `gorm:"column:user_id"`
	ScopesCSV  string     `gorm:"column:scopes_csv"`
	ServersCSV string     `gorm:"column:servers_csv"`
	ExpiresAt  *time.Time `gorm:"column:expires_at"`
}

func (patRecord) TableName() string { return "api_tokens" }

func (a *GORMAuthorizer) loadPAT(ctx context.Context, id uint64, subject Principal) (*patRecord, error) {
	if subject.Kind != UserPrincipal {
		return nil, errors.New("PAT subject must be user")
	}
	var row patRecord
	if err := a.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		return nil, err
	}
	owner, err := strconv.ParseUint(subject.ID, 10, 64)
	if err != nil || owner == 0 || row.UserID != owner || row.ExpiresAt != nil && !row.ExpiresAt.After(time.Now().UTC()) {
		return nil, errors.New("PAT is not active for subject")
	}
	// Parse the complete whitelist before evaluating the request. A malformed
	// value must never become an unrestricted token merely because the current
	// request targets a non-server resource.
	if _, ok := parseServerIDs(row.ServersCSV); !ok {
		return nil, errors.New("PAT has malformed server scope")
	}
	return &row, nil
}

func validResourceKind(k resource.Kind) bool {
	switch k {
	case resource.User, resource.Server, resource.APIToken, resource.Domain, resource.DNSZone, resource.DNSRecord, resource.DDNSBinding, resource.Certificate, resource.Workflow, resource.WorkflowRun, resource.Credential, resource.DeploymentTarget:
		return true
	default:
		return false
	}
}

func grantResourceMatches(grant, requested resource.Ref) bool {
	return grant.Kind == requested.Kind && (grant.ID == requested.ID || grant.ID == "*")
}

func containsAction(actions []Action, wanted Action) bool {
	for _, action := range actions {
		if action == wanted {
			return true
		}
	}
	return false
}

func grantTargetsRequest(grant PolicyGrant, req Request) bool {
	if len(grant.ServerIDs) > 0 && req.Resource.Kind == resource.Server {
		id, err := strconv.ParseUint(req.Resource.ID, 10, 64)
		if err != nil || !containsUint64(grant.ServerIDs, id) {
			return false
		}
	}
	if len(grant.DNS) > 0 {
		// A grant with an explicit DNS boundary must never authorize a request
		// that omitted the concrete names being operated on. Treat missing
		// server-resolved facts as an authorization failure rather than as an
		// empty set that happens to pass the loop below.
		if len(req.DNS) == 0 {
			return false
		}
		for _, requested := range req.DNS {
			matched := false
			for _, scope := range grant.DNS {
				if scope.Zone == requested.Zone && strings.EqualFold(scope.RecordType, requested.RecordType) && dnsPatternMatches(scope.Pattern, requested.Name) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	if len(grant.CertificateNames) > 0 {
		// Certificate scope is likewise fail-closed when the caller did not
		// provide the resolved SANs. The browser-supplied certificate label is
		// not sufficient evidence for this check.
		if len(req.CertificateNames) == 0 {
			return false
		}
		for _, requested := range req.CertificateNames {
			matched := false
			for _, pattern := range grant.CertificateNames {
				if dnsPatternMatches(pattern, requested) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

func dnsPatternMatches(pattern, value string) bool {
	pattern, value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), ".")), strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if pattern == value {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return value != base && strings.HasSuffix(value, "."+base)
	}
	return false
}

func patAllowsScope(scopes string, action Action, kind resource.Kind) bool {
	verb := map[Action]string{View: "read", Edit: "write", Execute: "exec", Delete: "delete", Export: "export", Download: "download", Use: "use", Reveal: "reveal", Rotate: "rotate", Grant: "grant"}[action]
	if verb == "" {
		return false
	}
	prefix := "nezha:" + string(kind) + ":"
	for _, raw := range strings.Split(scopes, ",") {
		scope := strings.TrimSpace(raw)
		if scope == "nezha:*" || scope == "nezha:admin:*" || scope == prefix+"*" || scope == prefix+verb || scope == prefix+string(action) {
			return true
		}
	}
	return false
}

func patAllowsResource(servers string, ref resource.Ref) bool {
	if servers == "" || ref.Kind != resource.Server {
		return true
	}
	id, err := strconv.ParseUint(ref.ID, 10, 64)
	if err != nil || id == 0 {
		return false
	}
	ids, ok := parseServerIDs(servers)
	return ok && containsUint64(ids, id)
}

func patIntersectsGrant(servers string, grant PolicyGrant, ref resource.Ref) bool {
	if ref.Kind != resource.Server || servers == "" || len(grant.ServerIDs) == 0 {
		return true
	}
	ids, ok := parseServerIDs(servers)
	if !ok {
		return false
	}
	for _, id := range grant.ServerIDs {
		if containsUint64(ids, id) {
			return true
		}
	}
	return false
}

func parseServerIDs(raw string) ([]uint64, bool) {
	if raw == "" {
		return nil, true
	}
	parts := strings.Split(raw, ",")
	ids := make([]uint64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		id, err := strconv.ParseUint(part, 10, 64)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != part {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

func containsUint64(values []uint64, wanted uint64) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
