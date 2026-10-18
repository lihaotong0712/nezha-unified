// Package dns defines the draft provider contract for centralized DNS management.
// It is not wired into Dashboard or the existing DDNS worker. See
// docs/DNS_PROVIDER_CONTRACT.md before implementing an adapter.
package dns

import (
	"context"
	"encoding/json"
	"time"
)

// ZoneID and RecordID are opaque remote identifiers, scoped to a provider
// account. They are not local resource IDs or authorization grants.
type ZoneID string
type RecordID string

type Zone struct {
	ID         ZoneID
	Name       string // Lowercase ASCII FQDN, including the trailing dot.
	AccessMode string // Provider value, e.g. EdgeOne "full"; empty if unknown.
	Status     string // Provider value; not an authorization decision.
}

type TTLMode string

const (
	TTLExplicit  TTLMode = "explicit"
	TTLAutomatic TTLMode = "automatic"
)

type TTL struct {
	Mode    TTLMode
	Seconds uint32 // Positive for explicit; zero for automatic.
}

// RecordData is a complete desired record, not a PATCH document. Updates must
// preserve fields copied from the current record unless explicitly changed.
type RecordData struct {
	Name       string // Lowercase ASCII FQDN with trailing dot; apex is zone.Name.
	Type       string // Uppercase, e.g. A, TXT, MX, SRV.
	Value      string // Complete RFC presentation RDATA, including MX/SRV priority.
	TTL        TTL
	Line       string                     // Opaque provider line ID; empty selects provider default.
	Weight     *uint16                    // nil means unset; zero is a real provider-specific value.
	Proxied    *bool                      // nil means inapplicable; false explicitly selects DNS only.
	Disabled   *bool                      // nil means inapplicable; true requires native support.
	Comment    *string                    // nil means absent; pointer to empty string clears a comment.
	Extensions map[string]json.RawMessage // Validated provider fields, never secrets.
}

type Record struct {
	ID RecordID
	RecordData
}

// PageRequest uses an adapter-owned cursor, bound to account, zone and filters.
// An empty cursor starts iteration. Limit must be positive and within limits
// advertised by the adapter. An empty result page can still have a next cursor.
type PageRequest struct {
	Cursor string
	Limit  uint32
}

type Page[T any] struct {
	Items      []T
	NextCursor string // Empty only when iteration has finished.
}

// RecordFilter fields are exact matches combined with AND. Empty fields do not
// filter. An adapter must post-filter a vendor's fuzzy search before returning.
type RecordFilter struct {
	Name string
	Type string
	Line string
}

type SupportState string

const (
	SupportUnknown     SupportState = ""
	SupportAvailable   SupportState = "available"
	SupportUnavailable SupportState = "unavailable"
)

type Support struct {
	State  SupportState
	Reason string // Constraints or the reason support could not be determined.
}

type Feature string

const (
	FeatureCreateRecord Feature = "create_record"
	FeatureUpdateRecord Feature = "update_record"
	FeatureDeleteRecord Feature = "delete_record"
	FeatureLines        Feature = "lines"
	FeatureWeight       Feature = "weight"
	FeatureProxy        Feature = "proxy"
	FeatureDisable      Feature = "disable"
	FeatureComment      Feature = "comment"
	FeatureDNSSECRead   Feature = "dnssec_read"
)

type TTLLimits struct {
	MinSeconds *uint32 // nil means not yet determined.
	MaxSeconds *uint32
	Automatic  Support
}

// Capabilities describes this account and zone at observation time. A missing
// feature or record type is unknown. Support never implies user permission.
// Per-type, plan and field combinations still require validation on each write.
type Capabilities struct {
	Features    map[Feature]Support
	RecordTypes map[string]Support
	TTL         TTLLimits
	MaxPageSize uint32 // Zero means unknown.
}

// Provider is bound to one account and credential version by the application
// service. Credentials and local authorization types are intentionally absent.
// Every network operation must honor ctx cancellation and deadlines.
type Provider interface {
	ListZones(ctx context.Context, page PageRequest) (Page[Zone], error)
	GetZone(ctx context.Context, id ZoneID) (Zone, error)
	Capabilities(ctx context.Context, zone Zone) (Capabilities, error)
	ListRecords(ctx context.Context, zone Zone, filter RecordFilter, page PageRequest) (Page[Record], error)
	GetRecord(ctx context.Context, zone Zone, id RecordID) (Record, error)
}

// RecordWriter is optional. Unsupported operations must fail before mutation.
// before must come from a fresh authorized read of the same account and zone.
// It supports conflict detection but does not promise remote atomic CAS.
// Never replace an entire same-name RRset to emulate an individual write.
type RecordWriter interface {
	CreateRecord(ctx context.Context, zone Zone, record RecordData) (Record, error)
	UpdateRecord(ctx context.Context, zone Zone, before Record, after RecordData) (Record, error)
	DeleteRecord(ctx context.Context, zone Zone, before Record) error
}

type Line struct {
	ID       string
	Name     string
	ParentID string
}

type LineReader interface {
	ListLines(ctx context.Context, zone Zone) ([]Line, error)
}

// DNSSECState describes the observed zone configuration. A DS RDATA value is not
// evidence that the parent delegation has published or validated the DS record.
type DNSSECState struct {
	Status string // Normalized by adapter; unknown must remain explicit.
	DS     []string
}

type DNSSECReader interface {
	GetDNSSEC(ctx context.Context, zone Zone) (DNSSECState, error)
}

type ChangeKind string

const (
	ChangeCreate ChangeKind = "create"
	ChangeUpdate ChangeKind = "update"
	ChangeDelete ChangeKind = "delete"
)

// Change requires After for create, Before and After for update, and Before
// for delete. Before includes the record ID and the last observed contents.
type Change struct {
	Kind   ChangeKind
	Before *Record
	After  *RecordData
}

type WriteOutcome string

const (
	OutcomeNotApplied WriteOutcome = "not_applied"
	OutcomeApplied    WriteOutcome = "applied"
	OutcomeUnknown    WriteOutcome = "unknown"
)

type ChangeResult struct {
	Index   int // Original input index, even if vendor execution order differs.
	Outcome WriteOutcome
	Record  *Record // Returned record for create/update, if known.
	Error   error
}

type BatchCapabilities struct {
	Kinds               []ChangeKind
	MaxChanges          uint32 // Zero means unknown, not unlimited.
	AtomicConfiguration bool   // Never promises atomic DNS propagation.
}

// BatchWriter is an optional native batch API. It must report a result for
// every input. A request-level error does not erase individual known outcomes.
// Application-level sequential batching uses RecordWriter instead.
type BatchWriter interface {
	BatchCapabilities(ctx context.Context, zone Zone) (BatchCapabilities, error)
	ApplyBatch(ctx context.Context, zone Zone, changes []Change) ([]ChangeResult, error)
}

type ErrorCode string

const (
	ErrorInvalidArgument ErrorCode = "invalid_argument"
	ErrorUnauthenticated ErrorCode = "unauthenticated"
	ErrorPermission      ErrorCode = "permission_denied"
	ErrorNotFound        ErrorCode = "not_found"
	ErrorConflict        ErrorCode = "conflict"
	ErrorUnsupported     ErrorCode = "unsupported"
	ErrorRateLimited     ErrorCode = "rate_limited"
	ErrorUnavailable     ErrorCode = "unavailable"
	ErrorCanceled        ErrorCode = "canceled"
	ErrorDeadline        ErrorCode = "deadline_exceeded"
	ErrorProvider        ErrorCode = "provider_error"
)

// ProviderError exposes sanitized diagnostics through errors.As. Error() must
// not contain credentials, request bodies, raw responses or unfiltered RDATA.
// A write timeout may be OutcomeUnknown; it must not trigger a blind retry.
// Cancellation errors must also unwrap to context.Canceled or DeadlineExceeded.
type ProviderError interface {
	error
	Code() ErrorCode
	VendorCode() string
	RequestID() string
	RetryAfter() time.Duration // Zero means no vendor hint, not immediate retry.
	Outcome() WriteOutcome
	RecordID() RecordID // Known remote ID, including after a failed read-back.
}
