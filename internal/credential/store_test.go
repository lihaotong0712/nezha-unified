package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type testAuthorizer struct{ allowed atomic.Bool }

type testRecorder struct {
	mu     sync.Mutex
	events []audit.Event
	fail   atomic.Bool
}

func (r *testRecorder) Record(_ context.Context, event audit.Event) error {
	if r.fail.Load() {
		return errors.New("audit storage unavailable")
	}
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
	return nil
}

func (a *testAuthorizer) Authorize(context.Context, authz.Request) (authz.Decision, error) {
	if !a.allowed.Load() {
		return authz.Decision{Allowed: false, PolicyVersion: "test-policy"}, nil
	}
	return authz.Decision{Allowed: true, PolicyVersion: "test-policy", GrantIDs: []string{"grant-test"}}, nil
}

func newCredentialStore(t *testing.T, allowed bool) (*Store, *testAuthorizer, *AESGCMProtector) {
	t.Helper()
	dsn := fmt.Sprintf("file:credential_test_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	})
	protector, err := NewAESGCMProtector("key-1", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &testAuthorizer{}
	authorizer.allowed.Store(allowed)
	store := NewStore(db, protector, authorizer)
	store.SetRecorder(&testRecorder{})
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store, authorizer, protector
}

func testBinding() Binding {
	return Binding{Purpose: DNSManage, Consumer: resource.Ref{Kind: resource.Workflow, ID: "workflow-1"}, Target: resource.Ref{Kind: resource.DNSZone, ID: "zone-1"}}
}

func testUseRequest(id string, version uint64) UseRequest {
	return UseRequest{
		Execution:    authz.Execution{Subject: authz.User(7), TriggeredBy: authz.User(7), Entry: authz.Session, OperationID: "operation-1"},
		Credential:   Ref{ID: id, Version: version},
		ExpectedType: "cloudflare.api_token",
		Binding:      testBinding(),
		Action:       authz.Use,
	}
}

func createTestCredential(t *testing.T, store *Store) Metadata {
	t.Helper()
	metadata, err := store.Create(context.Background(), CreateRequest{ID: "cred-1", OwnerID: 7, Name: "Cloudflare", Type: "cloudflare.api_token", Bindings: []Binding{testBinding()}, Secret: NewSecret([]byte("super-secret"))})
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestStoreWithSecretDestroysSecretAndReturnsOnlyMetadata(t *testing.T) {
	store, _, _ := newCredentialStore(t, true)
	metadata := createTestCredential(t, store)
	if metadata.CurrentVersion != 1 || metadata.Resource.State != resource.Active || metadata.Bindings[0] != testBinding() {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	var callbackSecret *Secret
	var callbackValue string
	if err := store.WithSecret(context.Background(), testUseRequest("cred-1", 0), func(_ context.Context, resolved Resolved) error {
		callbackSecret = resolved.Secret
		callbackValue = string(resolved.Secret.Bytes())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if callbackValue != "super-secret" {
		t.Fatalf("callback received %q", callbackValue)
	}
	if callbackSecret == nil || callbackSecret.Bytes() != nil {
		t.Fatal("WithSecret did not destroy callback secret")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || containsSecret(string(encoded), "super-secret") {
		t.Fatalf("metadata leaked secret: %s", encoded)
	}
	var records []Record
	if err := store.db.Find(&records).Error; err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("stored %d credential records", len(records))
	}
}

func TestStoreWithSecretDestroysSecretWhenCallbackFailsOrPanics(t *testing.T) {
	store, _, _ := newCredentialStore(t, true)
	createTestCredential(t, store)
	var callbackSecret *Secret
	callbackErr := errors.New("provider failed")
	if err := store.WithSecret(context.Background(), testUseRequest("cred-1", 1), func(_ context.Context, resolved Resolved) error {
		callbackSecret = resolved.Secret
		return callbackErr
	}); !errors.Is(err, callbackErr) {
		t.Fatalf("callback error = %v", err)
	}
	if callbackSecret == nil || callbackSecret.Bytes() != nil {
		t.Fatal("callback error did not destroy secret")
	}
	callbackSecret = nil
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("callback panic was not propagated")
			}
		}()
		_ = store.WithSecret(context.Background(), testUseRequest("cred-1", 1), func(_ context.Context, resolved Resolved) error {
			callbackSecret = resolved.Secret
			panic("provider panic")
		})
	}()
	if callbackSecret == nil || callbackSecret.Bytes() != nil {
		t.Fatal("callback panic did not destroy secret")
	}
}

func TestStoreRejectsAuthorizationFailureAndBindingOrTypeMismatch(t *testing.T) {
	store, authorizer, _ := newCredentialStore(t, true)
	createTestCredential(t, store)
	authorizer.allowed.Store(false)
	var platformError *platformerr.Error
	if err := store.WithSecret(context.Background(), testUseRequest("cred-1", 1), func(context.Context, Resolved) error { return nil }); !errors.As(err, &platformError) || platformError.Code != platformerr.Forbidden {
		t.Fatalf("authorization failure = %v", err)
	}
	authorizer.allowed.Store(true)
	request := testUseRequest("cred-1", 1)
	request.ExpectedType = "other.type"
	if err := store.WithSecret(context.Background(), request, func(context.Context, Resolved) error { return nil }); !errors.Is(err, ErrCredentialType) {
		t.Fatalf("type mismatch = %v", err)
	}
	request = testUseRequest("cred-1", 1)
	request.Binding.Target.ID = "other-zone"
	if err := store.WithSecret(context.Background(), request, func(context.Context, Resolved) error { return nil }); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("binding mismatch = %v", err)
	}
}

func TestStoreVersionRotationRevocationAndDisable(t *testing.T) {
	store, _, _ := newCredentialStore(t, true)
	createTestCredential(t, store)
	version, err := store.Rotate(context.Background(), RotateRequest{Credential: Ref{ID: "cred-1"}, Secret: NewSecret([]byte("rotated-secret"))})
	if err != nil || version != 2 {
		t.Fatalf("rotate version=%d err=%v", version, err)
	}
	var got string
	if err := store.WithSecret(context.Background(), testUseRequest("cred-1", 0), func(_ context.Context, resolved Resolved) error { got = string(resolved.Secret.Bytes()); return nil }); err != nil || got != "rotated-secret" {
		t.Fatalf("current version got=%q err=%v", got, err)
	}
	if err := store.RevokeVersion(context.Background(), Ref{ID: "cred-1", Version: 2}); err != nil {
		t.Fatal(err)
	}
	if err := store.WithSecret(context.Background(), testUseRequest("cred-1", 2), func(context.Context, Resolved) error { return nil }); !errors.Is(err, ErrVersionRevoked) {
		t.Fatalf("revoked version = %v", err)
	}
	if err := store.Disable(context.Background(), Ref{ID: "cred-1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.WithSecret(context.Background(), testUseRequest("cred-1", 1), func(context.Context, Resolved) error { return nil }); !errors.Is(err, ErrCredentialDisabled) {
		t.Fatalf("disabled credential = %v", err)
	}
	if err := store.Enable(context.Background(), Ref{ID: "cred-1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), Ref{ID: "cred-1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.WithSecret(context.Background(), testUseRequest("cred-1", 1), func(context.Context, Resolved) error { return nil }); !errors.Is(err, ErrCredentialDeleted) {
		t.Fatalf("deleted credential = %v", err)
	}
}

func TestAESGCMProtectorBindsCredentialAndVersion(t *testing.T) {
	protector, err := NewAESGCMProtector("key-1", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ref := resource.Ref{Kind: resource.Credential, ID: "cred-1"}
	encrypted, err := protector.Seal(context.Background(), ref, 3, NewSecret([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protector.Open(context.Background(), ref, 2, encrypted); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("wrong version open = %v", err)
	}
	if _, err := protector.Open(context.Background(), resource.Ref{Kind: resource.Credential, ID: "cred-2"}, 3, encrypted); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("wrong credential open = %v", err)
	}
	encrypted.Ciphertext[0] ^= 0xff
	if _, err := protector.Open(context.Background(), ref, 3, encrypted); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("tampered open = %v", err)
	}
}

func TestStoreDoesNotPersistPlaintextSecret(t *testing.T) {
	store, _, _ := newCredentialStore(t, true)
	createTestCredential(t, store)
	var version VersionRecord
	if err := store.db.First(&version, "credential_id = ? AND version = ?", "cred-1", 1).Error; err != nil {
		t.Fatal(err)
	}
	if string(version.Ciphertext) == "super-secret" || string(version.Nonce) == "super-secret" {
		t.Fatal("plaintext credential was stored")
	}
}

func TestStoreConcurrentReadsAndStateChangesAreSerialized(t *testing.T) {
	store, _, _ := newCredentialStore(t, true)
	createTestCredential(t, store)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := store.WithSecret(context.Background(), testUseRequest("cred-1", 1), func(context.Context, Resolved) error { return nil }); err != nil && !errors.Is(err, ErrCredentialDisabled) {
				t.Errorf("concurrent use: %v", err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := store.Disable(context.Background(), Ref{ID: "cred-1"}); err != nil {
			t.Errorf("concurrent disable: %v", err)
		}
	}()
	wg.Wait()
}

func containsSecret(value, secret string) bool {
	return len(secret) > 0 && len(value) >= len(secret) && strings.Contains(value, secret)
}
