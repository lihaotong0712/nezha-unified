package dns

// Service coordinates local DNS resource bindings, authorization and provider
// calls. Providers never receive caller identity or local resource IDs; the
// service resolves those facts before invoking an adapter.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
)

// ZoneBinding is the local, authorized mapping to one provider zone. Remote
// IDs remain opaque and are never accepted as a substitute for Ref.
type ZoneBinding struct {
	Ref        resource.Ref   `json:"ref"`
	OwnerID    uint64         `json:"owner_id"`
	Provider   string         `json:"provider"`
	Remote     Zone           `json:"remote"`
	Credential resource.Ref   `json:"credential,omitempty"`
	Revision   uint64         `json:"revision"`
	State      resource.State `json:"state"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

func (z ZoneBinding) Validate() error {
	if z.Ref.Kind != resource.DNSZone || z.Ref.Validate() != nil || z.OwnerID == 0 || z.Remote.ID == "" || z.Remote.Name == "" || strings.TrimSpace(z.Provider) == "" {
		return errors.New("invalid DNS zone binding")
	}
	if z.Credential.ID != "" && (z.Credential.Kind != resource.Credential || z.Credential.Validate() != nil) {
		return errors.New("invalid DNS zone credential reference")
	}
	if z.Revision == 0 {
		return errors.New("invalid DNS zone revision")
	}
	if z.State == "" {
		return errors.New("invalid DNS zone state")
	}
	return nil
}

// BindingStore is intentionally narrow, so a GORM-backed registry can replace
// the in-memory implementation without changing the application service.
type BindingStore interface {
	Create(context.Context, ZoneBinding) error
	Get(context.Context, resource.Ref) (ZoneBinding, error)
	List(context.Context, uint64) ([]ZoneBinding, error)
}

// MemoryStore is suitable for tests and small single-process deployments. It
// is concurrency-safe and rejects duplicate local resource IDs.
type MemoryStore struct {
	mu    sync.RWMutex
	items map[string]ZoneBinding
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{items: make(map[string]ZoneBinding)} }

func (s *MemoryStore) Create(ctx context.Context, binding ZoneBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || binding.Validate() != nil {
		return errors.New("invalid DNS zone binding")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[binding.Ref.ID]; ok {
		return errors.New("DNS zone binding already exists")
	}
	s.items[binding.Ref.ID] = binding
	return nil
}

func (s *MemoryStore) Get(ctx context.Context, ref resource.Ref) (ZoneBinding, error) {
	if err := ctx.Err(); err != nil {
		return ZoneBinding{}, err
	}
	if s == nil || ref.Kind != resource.DNSZone || ref.Validate() != nil {
		return ZoneBinding{}, errors.New("invalid DNS zone reference")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, ok := s.items[ref.ID]
	if !ok || binding.State == resource.Deleted {
		return ZoneBinding{}, errors.New("DNS zone not found")
	}
	return binding, nil
}

func (s *MemoryStore) List(ctx context.Context, ownerID uint64) ([]ZoneBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || ownerID == 0 {
		return nil, errors.New("invalid DNS zone owner")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ZoneBinding, 0)
	for _, binding := range s.items {
		if binding.OwnerID == ownerID && binding.State != resource.Deleted {
			out = append(out, binding)
		}
	}
	return out, nil
}

// ProviderFactory resolves a validated credential reference into a provider.
// It is called for every operation, allowing credential revocation to take
// effect without retaining provider clients or secrets in the service.
// The execution and action are passed through so credential use can preserve
// the caller's PAT/session restrictions at the provider boundary.
type ProviderFactory func(context.Context, authz.Execution, authz.Action, ZoneBinding) (Provider, error)

type Authorizer interface {
	Authorize(context.Context, authz.Request) (authz.Decision, error)
}

type Service struct {
	store      BindingStore
	authorizer Authorizer
	recorder   audit.Recorder
	factory    ProviderFactory
	newID      func() (string, error)
	now        func() time.Time
}

func NewService(store BindingStore, authorizer Authorizer, recorder audit.Recorder, factory ProviderFactory) *Service {
	return &Service{store: store, authorizer: authorizer, recorder: recorder, factory: factory, newID: newDNSID, now: time.Now}
}

func newDNSID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "dns-" + hex.EncodeToString(b[:]), nil
}

func (s *Service) ListZones(ctx context.Context, execution authz.Execution, ownerID uint64) ([]ZoneBinding, error) {
	if s == nil || s.store == nil {
		return nil, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	items, err := s.store.List(ctx, ownerID)
	if err != nil {
		return nil, platformerr.From(err, execution.OperationID)
	}
	out := make([]ZoneBinding, 0, len(items))
	for _, item := range items {
		if _, err := s.check(ctx, execution, authz.View, item, nil); err == nil {
			out = append(out, item)
		} else {
			var policyErr *platformerr.Error
			if !errors.As(err, &policyErr) || policyErr.Code != platformerr.Forbidden {
				return nil, err
			}
		}
	}
	return out, nil
}

func (s *Service) ListRecords(ctx context.Context, execution authz.Execution, ref resource.Ref, filter RecordFilter, page PageRequest) (Page[Record], error) {
	binding, err := s.loadBinding(ctx, execution, ref)
	if err != nil {
		return Page[Record]{}, err
	}
	var facts []authz.DNSName
	if filter.Name != "" && filter.Type != "" {
		facts = dnsFacts(binding, filter.Name, filter.Type)
	}
	if _, err := s.check(ctx, execution, authz.View, binding, facts); err != nil {
		return Page[Record]{}, err
	}
	provider, err := s.resolveProvider(ctx, execution, authz.View, binding)
	if err != nil {
		return Page[Record]{}, err
	}
	result, err := provider.ListRecords(ctx, binding.Remote, filter, page)
	if err != nil {
		return Page[Record]{}, fromProviderError(err, execution.OperationID)
	}
	return result, nil
}

func (s *Service) GetRecord(ctx context.Context, execution authz.Execution, ref resource.Ref, id RecordID) (Record, error) {
	binding, err := s.loadBinding(ctx, execution, ref)
	if err != nil {
		return Record{}, err
	}
	if _, err := s.check(ctx, execution, authz.View, binding, nil); err != nil {
		return Record{}, err
	}
	provider, err := s.resolveProvider(ctx, execution, authz.View, binding)
	if err != nil {
		return Record{}, err
	}
	record, err := provider.GetRecord(ctx, binding.Remote, id)
	if err != nil {
		return Record{}, fromProviderError(err, execution.OperationID)
	}
	if _, err := s.check(ctx, execution, authz.View, binding, dnsFacts(binding, record.Name, record.Type)); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Service) CreateRecord(ctx context.Context, execution authz.Execution, ref resource.Ref, data RecordData) (Record, error) {
	binding, err := s.loadBinding(ctx, execution, ref)
	if err != nil {
		return Record{}, err
	}
	decision, err := s.check(ctx, execution, authz.Edit, binding, dnsFacts(binding, data.Name, data.Type))
	if err != nil {
		return Record{}, err
	}
	provider, err := s.resolveProvider(ctx, execution, authz.Edit, binding)
	if err != nil {
		return Record{}, err
	}
	if err := s.requireCapability(ctx, provider, binding.Remote, FeatureCreateRecord); err != nil {
		return Record{}, fromProviderError(err, execution.OperationID)
	}
	if err := s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "create-requested", binding.Ref.ID), Time: s.now(), Execution: execution, Action: authz.Edit, Resource: binding.Ref, Outcome: audit.Requested, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: binding.Revision}); err != nil {
		return Record{}, err
	}
	record, err := provider.(RecordWriter).CreateRecord(ctx, binding.Remote, data)
	if err != nil {
		_ = s.recordFailure(ctx, execution, authz.Edit, binding.Ref, decision, binding.Revision, err, "create-failed")
		return Record{}, fromProviderError(err, execution.OperationID)
	}
	_ = s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "create-succeeded", string(record.ID)), Time: s.now(), Execution: execution, Action: authz.Edit, Resource: binding.Ref, Outcome: audit.Succeeded, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: binding.Revision})
	return record, nil
}

func (s *Service) UpdateRecord(ctx context.Context, execution authz.Execution, ref resource.Ref, before Record, after RecordData) (Record, error) {
	binding, err := s.loadBinding(ctx, execution, ref)
	if err != nil {
		return Record{}, err
	}
	decision, err := s.check(ctx, execution, authz.Edit, binding, dnsFacts(binding, before.Name, before.Type, after.Name, after.Type))
	if err != nil {
		return Record{}, err
	}
	provider, err := s.resolveProvider(ctx, execution, authz.Edit, binding)
	if err != nil {
		return Record{}, err
	}
	if err := s.requireCapability(ctx, provider, binding.Remote, FeatureUpdateRecord); err != nil {
		return Record{}, fromProviderError(err, execution.OperationID)
	}
	if err := s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "update-requested", string(before.ID)), Time: s.now(), Execution: execution, Action: authz.Edit, Resource: binding.Ref, Outcome: audit.Requested, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: binding.Revision}); err != nil {
		return Record{}, err
	}
	writer, ok := provider.(RecordWriter)
	if !ok {
		return Record{}, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	record, err := writer.UpdateRecord(ctx, binding.Remote, before, after)
	if err != nil {
		_ = s.recordFailure(ctx, execution, authz.Edit, binding.Ref, decision, binding.Revision, err, "update-failed")
		return Record{}, fromProviderError(err, execution.OperationID)
	}
	_ = s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "update-succeeded", string(record.ID)), Time: s.now(), Execution: execution, Action: authz.Edit, Resource: binding.Ref, Outcome: audit.Succeeded, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: binding.Revision})
	return record, nil
}

func (s *Service) DeleteRecord(ctx context.Context, execution authz.Execution, ref resource.Ref, before Record) error {
	binding, err := s.loadBinding(ctx, execution, ref)
	if err != nil {
		return err
	}
	decision, err := s.check(ctx, execution, authz.Delete, binding, dnsFacts(binding, before.Name, before.Type))
	if err != nil {
		return err
	}
	provider, err := s.resolveProvider(ctx, execution, authz.Delete, binding)
	if err != nil {
		return err
	}
	if err := s.requireCapability(ctx, provider, binding.Remote, FeatureDeleteRecord); err != nil {
		return fromProviderError(err, execution.OperationID)
	}
	if err := s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "delete-requested", string(before.ID)), Time: s.now(), Execution: execution, Action: authz.Delete, Resource: binding.Ref, Outcome: audit.Requested, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: binding.Revision}); err != nil {
		return err
	}
	writer, ok := provider.(RecordWriter)
	if !ok {
		return platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	if err := writer.DeleteRecord(ctx, binding.Remote, before); err != nil {
		_ = s.recordFailure(ctx, execution, authz.Delete, binding.Ref, decision, binding.Revision, err, "delete-failed")
		return fromProviderError(err, execution.OperationID)
	}
	return s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "delete-succeeded", string(before.ID)), Time: s.now(), Execution: execution, Action: authz.Delete, Resource: binding.Ref, Outcome: audit.Succeeded, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: binding.Revision})
}

func (s *Service) loadBinding(ctx context.Context, execution authz.Execution, ref resource.Ref) (ZoneBinding, error) {
	if s == nil || s.store == nil {
		return ZoneBinding{}, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	binding, err := s.store.Get(ctx, ref)
	if err != nil {
		return ZoneBinding{}, platformerr.From(err, execution.OperationID)
	}
	if binding.State != resource.Active {
		return ZoneBinding{}, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	return binding, nil
}

func (s *Service) resolveProvider(ctx context.Context, execution authz.Execution, action authz.Action, binding ZoneBinding) (Provider, error) {
	if s == nil || s.factory == nil {
		return nil, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	provider, err := s.factory(ctx, execution, action, binding)
	if err != nil {
		return nil, platformerr.From(err, execution.OperationID)
	}
	if provider == nil {
		return nil, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	return provider, nil
}

func (s *Service) check(ctx context.Context, execution authz.Execution, action authz.Action, binding ZoneBinding, facts []authz.DNSName) (authz.Decision, error) {
	if s.authorizer == nil {
		return authz.Decision{}, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	return authz.Check(ctx, s.authorizer, authz.Request{Execution: execution, Action: action, Resource: binding.Ref, DNS: facts})
}

func (s *Service) requireCapability(ctx context.Context, provider Provider, zone Zone, feature Feature) error {
	capabilities, err := provider.Capabilities(ctx, zone)
	if err != nil {
		return err
	}
	support, ok := capabilities.Features[feature]
	if !ok || support.State != SupportAvailable {
		return fmt.Errorf("DNS feature %s is not available", feature)
	}
	if _, ok := provider.(RecordWriter); !ok {
		return errors.New("DNS provider does not support record writes")
	}
	return nil
}

func (s *Service) record(ctx context.Context, event audit.Event) error {
	if s.recorder == nil {
		return nil
	}
	if err := s.recorder.Record(ctx, event); err != nil {
		return platformerr.From(err, event.Execution.OperationID)
	}
	return nil
}

func (s *Service) recordFailure(ctx context.Context, execution authz.Execution, action authz.Action, ref resource.Ref, decision authz.Decision, revision uint64, operation error, stage string) error {
	return s.record(ctx, audit.Event{ID: eventID(execution.OperationID, stage, ref.ID), Time: s.now(), Execution: execution, Action: action, Resource: ref, Outcome: audit.Failed, Code: fromProviderError(operation, execution.OperationID).Code, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: revision})
}

// fromProviderError converts adapter errors into the public platform error
// vocabulary. ProviderError.Error is deliberately safe for logs, but callers
// still need a stable API code and HTTP status rather than an internal error.
// Unknown errors at a provider boundary are classified as provider failures
// so implementation details never escape through the Dashboard API.
func fromProviderError(err error, operationID string) *platformerr.Error {
	if err == nil {
		return nil
	}
	var providerErr ProviderError
	if !errors.As(err, &providerErr) {
		if errors.Is(err, context.Canceled) {
			return platformerr.New(platformerr.Canceled, operationID, err)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return platformerr.New(platformerr.Timeout, operationID, err)
		}
		return platformerr.New(platformerr.ProviderFailure, operationID, err)
	}
	code := platformerr.ProviderFailure
	switch providerErr.Code() {
	case ErrorInvalidArgument:
		code = platformerr.InvalidArgument
	case ErrorUnauthenticated:
		code = platformerr.Unauthenticated
	case ErrorPermission:
		code = platformerr.Forbidden
	case ErrorNotFound:
		code = platformerr.NotFound
	case ErrorConflict:
		code = platformerr.Conflict
	case ErrorRateLimited, ErrorUnavailable:
		code = platformerr.Unavailable
	case ErrorCanceled:
		code = platformerr.Canceled
	case ErrorDeadline:
		code = platformerr.Timeout
	case ErrorUnsupported, ErrorProvider:
		code = platformerr.ProviderFailure
	}
	return platformerr.New(code, operationID, err)
}

func eventID(operation, stage, id string) string {
	return strings.Join([]string{operation, "dns", stage, id}, ":")
}

func dnsFacts(binding ZoneBinding, namesAndTypes ...string) []authz.DNSName {
	if len(namesAndTypes)%2 != 0 {
		return nil
	}
	facts := make([]authz.DNSName, 0, len(namesAndTypes)/2)
	for i := 0; i < len(namesAndTypes); i += 2 {
		facts = append(facts, authz.DNSName{Zone: binding.Ref, Name: namesAndTypes[i], RecordType: namesAndTypes[i+1]})
	}
	return facts
}
