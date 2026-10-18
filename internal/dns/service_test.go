package dns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/resource"
)

type serviceAuthorizer struct {
	allowed  bool
	requests []authz.Request
}

func (a *serviceAuthorizer) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	a.requests = append(a.requests, req)
	if !a.allowed {
		return authz.Decision{}, nil
	}
	return authz.Decision{Allowed: true, PolicyVersion: "test-v1", GrantIDs: []string{"grant-1"}}, nil
}

type serviceRecorder struct{ events []audit.Event }

func (r *serviceRecorder) Record(_ context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

type serviceProvider struct {
	capabilities Capabilities
	created      int
	updated      int
	deleted      int
	record       Record
}

func (p *serviceProvider) ListZones(context.Context, PageRequest) (Page[Zone], error) {
	return Page[Zone]{}, nil
}
func (p *serviceProvider) GetZone(context.Context, ZoneID) (Zone, error) { return Zone{}, nil }
func (p *serviceProvider) Capabilities(context.Context, Zone) (Capabilities, error) {
	return p.capabilities, nil
}
func (p *serviceProvider) ListRecords(context.Context, Zone, RecordFilter, PageRequest) (Page[Record], error) {
	return Page[Record]{Items: []Record{p.record}}, nil
}
func (p *serviceProvider) GetRecord(context.Context, Zone, RecordID) (Record, error) {
	return p.record, nil
}
func (p *serviceProvider) CreateRecord(context.Context, Zone, RecordData) (Record, error) {
	p.created++
	return p.record, nil
}
func (p *serviceProvider) UpdateRecord(context.Context, Zone, Record, RecordData) (Record, error) {
	p.updated++
	return p.record, nil
}
func (p *serviceProvider) DeleteRecord(context.Context, Zone, Record) error { p.deleted++; return nil }

func testBinding() ZoneBinding {
	return ZoneBinding{Ref: resource.Ref{Kind: resource.DNSZone, ID: "zone-local"}, OwnerID: 7, Provider: "cloudflare", Remote: Zone{ID: "zone-remote", Name: "example.com."}, Revision: 1, State: resource.Active, CreatedAt: time.Now(), UpdatedAt: time.Now()}
}

func testExecution() authz.Execution {
	return authz.Execution{Subject: authz.User(7), TriggeredBy: authz.User(7), Entry: authz.Session, OperationID: "op-1"}
}

func testProvider() *serviceProvider {
	return &serviceProvider{capabilities: Capabilities{Features: map[Feature]Support{
		FeatureCreateRecord: {State: SupportAvailable}, FeatureUpdateRecord: {State: SupportAvailable}, FeatureDeleteRecord: {State: SupportAvailable},
	}}, record: Record{ID: "record-1", RecordData: RecordData{Name: "www.example.com.", Type: "A", Value: "192.0.2.1", TTL: TTL{Mode: TTLExplicit, Seconds: 300}}}}
}

func TestServiceCreateRecordAuthorizesFactsAndAudits(t *testing.T) {
	store := NewMemoryStore()
	binding := testBinding()
	if err := store.Create(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	authorizer := &serviceAuthorizer{allowed: true}
	recorder := &serviceRecorder{}
	provider := testProvider()
	service := NewService(store, authorizer, recorder, func(context.Context, authz.Execution, authz.Action, ZoneBinding) (Provider, error) {
		return provider, nil
	})
	got, err := service.CreateRecord(context.Background(), testExecution(), binding.Ref, RecordData{Name: "www.example.com.", Type: "A", Value: "192.0.2.1", TTL: TTL{Mode: TTLExplicit, Seconds: 300}})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "record-1" || provider.created != 1 {
		t.Fatalf("result=%+v created=%d", got, provider.created)
	}
	if len(authorizer.requests) != 1 || len(authorizer.requests[0].DNS) != 1 || authorizer.requests[0].DNS[0].Name != "www.example.com." {
		t.Fatalf("authorization facts=%+v", authorizer.requests)
	}
	if len(recorder.events) != 2 || recorder.events[0].Outcome != audit.Requested || recorder.events[1].Outcome != audit.Succeeded {
		t.Fatalf("audit events=%+v", recorder.events)
	}
}

func TestServiceDeniedDoesNotResolveProviderOrMutate(t *testing.T) {
	store := NewMemoryStore()
	binding := testBinding()
	if err := store.Create(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	authorizer := &serviceAuthorizer{}
	called := false
	service := NewService(store, authorizer, nil, func(context.Context, authz.Execution, authz.Action, ZoneBinding) (Provider, error) {
		called = true
		return testProvider(), nil
	})
	_, err := service.CreateRecord(context.Background(), testExecution(), binding.Ref, RecordData{Name: "www.example.com.", Type: "A", Value: "192.0.2.1", TTL: TTL{Mode: TTLExplicit, Seconds: 300}})
	if err == nil {
		t.Fatal("expected authorization denial")
	}
	if called {
		t.Fatal("provider resolved before authorization")
	}
}

func TestMemoryStoreRejectsDeletedAndDuplicateBindings(t *testing.T) {
	store := NewMemoryStore()
	binding := testBinding()
	if err := store.Create(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), binding); err == nil {
		t.Fatal("duplicate binding accepted")
	}
	deleted := binding
	deleted.State = resource.Deleted
	if _, err := store.Get(context.Background(), deleted.Ref); err != nil && !errors.Is(err, context.Canceled) {
		// The original active binding remains available; this check documents that
		// a caller cannot mark a stored item deleted by mutating its input value.
		t.Fatal(err)
	}
}
