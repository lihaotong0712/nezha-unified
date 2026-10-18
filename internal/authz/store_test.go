package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newAuthzStoreTest(t *testing.T) *GORMAuthorizer {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", name)), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&patRecord{}); err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewGORMAuthorizer(db)
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}

func serverGrant(id string, serverIDs ...uint64) PolicyGrant {
	return PolicyGrant{ID: id, Principal: User(7), Resource: resource.Ref{Kind: resource.Server, ID: "*"}, Actions: []Action{View}, ServerIDs: serverIDs, PolicyVersion: "policy-1", Enabled: true}
}

func TestGORMAuthorizerIntersectsPATAndGrantServerScopes(t *testing.T) {
	authorizer := newAuthzStoreTest(t)
	if err := authorizer.PutGrant(context.Background(), serverGrant("grant-1", 2, 3)); err != nil {
		t.Fatal(err)
	}
	if err := authorizer.db.Create(&patRecord{ID: 11, UserID: 7, ScopesCSV: "nezha:server:read", ServersCSV: "2"}).Error; err != nil {
		t.Fatal(err)
	}
	base := Execution{Subject: User(7), TriggeredBy: User(7), Entry: PAT, TokenID: 11, OperationID: "op-1"}
	allowed, err := authorizer.Authorize(context.Background(), Request{Execution: base, Action: View, Resource: resource.Ref{Kind: resource.Server, ID: "2"}})
	if err != nil || !allowed.Allowed || allowed.PolicyVersion != "policy-1" || len(allowed.GrantIDs) != 1 {
		t.Fatalf("allowed = %+v, %v", allowed, err)
	}
	for _, id := range []string{"3", "4"} {
		decision, err := authorizer.Authorize(context.Background(), Request{Execution: base, Action: View, Resource: resource.Ref{Kind: resource.Server, ID: id}})
		if err != nil || decision.Allowed {
			t.Fatalf("server %s decision = %+v, %v; PAT whitelist must intersect policy", id, decision, err)
		}
	}
}

func TestGORMAuthorizerNeverTreatsMalformedOrExpiredPATAsUnlimited(t *testing.T) {
	authorizer := newAuthzStoreTest(t)
	if err := authorizer.PutGrant(context.Background(), serverGrant("grant-1")); err != nil {
		t.Fatal(err)
	}
	for _, pat := range []patRecord{
		{ID: 12, UserID: 7, ScopesCSV: "nezha:server:read", ServersCSV: "not-a-number"},
		{ID: 13, UserID: 7, ScopesCSV: "nezha:server:read", ServersCSV: "18446744073709551616"},
		{ID: 14, UserID: 7, ScopesCSV: "nezha:server:read", ExpiresAt: func() *time.Time { value := time.Now().UTC().Add(-time.Minute); return &value }()},
	} {
		if err := authorizer.db.Create(&pat).Error; err != nil {
			t.Fatal(err)
		}
		request := Request{Execution: Execution{Subject: User(7), TriggeredBy: User(7), Entry: PAT, TokenID: pat.ID, OperationID: fmt.Sprintf("op-%d", pat.ID)}, Action: View, Resource: resource.Ref{Kind: resource.Server, ID: "2"}}
		decision, err := authorizer.Authorize(context.Background(), request)
		if err != nil || decision.Allowed {
			t.Fatalf("PAT %d decision = %+v, %v; malformed/expired PAT must deny", pat.ID, decision, err)
		}
	}
}

func TestGORMAuthorizerRejectsMalformedPATWhitelistForEveryResource(t *testing.T) {
	authorizer := newAuthzStoreTest(t)
	grant := serverGrant("grant-workflow")
	grant.Resource = resource.Ref{Kind: resource.Workflow, ID: "workflow-1"}
	if err := authorizer.PutGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	if err := authorizer.db.Create(&patRecord{ID: 15, UserID: 7, ScopesCSV: "nezha:workflow:read", ServersCSV: "not-a-number"}).Error; err != nil {
		t.Fatal(err)
	}
	request := Request{Execution: Execution{Subject: User(7), TriggeredBy: User(7), Entry: PAT, TokenID: 15, OperationID: "op-15"}, Action: View, Resource: resource.Ref{Kind: resource.Workflow, ID: "workflow-1"}}
	decision, err := authorizer.Authorize(context.Background(), request)
	if err != nil || decision.Allowed {
		t.Fatalf("malformed PAT whitelist decision = %+v, %v; malformed token must deny every resource", decision, err)
	}
}

func TestGORMAuthorizerReloadsAndFiltersCurrentGrants(t *testing.T) {
	authorizer := newAuthzStoreTest(t)
	if err := authorizer.PutGrant(context.Background(), serverGrant("grant-1", 2)); err != nil {
		t.Fatal(err)
	}
	execution := Execution{Subject: User(7), TriggeredBy: User(7), Entry: Session, OperationID: "op-filter"}
	refs := []resource.Ref{{Kind: resource.Server, ID: "2"}, {Kind: resource.Server, ID: "3"}}
	filtered, err := authorizer.Filter(context.Background(), execution, View, refs)
	if err != nil || len(filtered) != 1 || filtered[0].ID != "2" {
		t.Fatalf("filtered = %+v, %v", filtered, err)
	}
	if err := authorizer.DeleteGrant(context.Background(), "grant-1"); err != nil {
		t.Fatal(err)
	}
	decision, err := authorizer.Authorize(context.Background(), Request{Execution: execution, Action: View, Resource: refs[0]})
	if err != nil || decision.Allowed {
		t.Fatalf("deleted grant decision = %+v, %v", decision, err)
	}
	if err := authorizer.PutGrant(context.Background(), serverGrant("grant-2", 2)); err != nil {
		t.Fatal(err)
	}
	if err := authorizer.PutGrant(context.Background(), serverGrant("grant-2", 3)); !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("reused grant ID error = %v, want conflict", err)
	}
}
