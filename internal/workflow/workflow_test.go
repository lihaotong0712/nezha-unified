package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type allowAuthorizer struct{ deny authz.Action }

func (a allowAuthorizer) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	if req.Action == a.deny {
		return authz.Decision{Allowed: false, PolicyVersion: "test-v1"}, nil
	}
	return authz.Decision{Allowed: true, PolicyVersion: "test-v1", GrantIDs: []string{"test-grant"}}, nil
}
func testExecution() authz.Execution {
	return authz.Execution{Subject: authz.User(7), TriggeredBy: authz.User(7), Entry: authz.Session, OperationID: "workflow-test"}
}
func newStore(t *testing.T) *GORMStore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewGORMStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestValidateDefinitionCanonicalDigest(t *testing.T) {
	norm, digest, err := ValidateDefinition([]byte(`{"nodes":[{"type":"issue"}],"enabled":true}`))
	if err != nil || digest == "" {
		t.Fatalf("validate = %q %v", digest, err)
	}
	if string(norm) != `{"enabled":true,"nodes":[{"type":"issue"}]}` {
		t.Fatalf("normalized = %s", norm)
	}
	if _, _, err := ValidateDefinition([]byte(`[]`)); err == nil {
		t.Fatal("array definition accepted")
	}
}
func TestWorkflowLifecyclePersistsVersionSnapshotAndRun(t *testing.T) {
	s := NewService(newStore(t), allowAuthorizer{}, nil)
	ctx := context.Background()
	e := testExecution()
	w, err := s.Create(ctx, CreateRequest{Execution: e, OwnerID: 7, Name: "renew-production", Definition: json.RawMessage(`{"nodes":[{"type":"issue"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	versions, err := s.Versions(ctx, e, w.Ref)
	if err != nil || len(versions) != 1 {
		t.Fatalf("versions = %+v %v", versions, err)
	}
	draft := versions[0]
	published, err := s.Publish(ctx, e, w.Ref, draft.Number)
	if err != nil {
		t.Fatal(err)
	}
	if published.State != StateActive || published.CurrentVersion != 1 {
		t.Fatalf("published = %+v", published)
	}
	run, err := s.StartRun(ctx, StartRunRequest{Execution: e, Workflow: w.Ref})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != RunPending || run.Digest != draft.Digest || string(run.Definition) != string(draft.Definition) {
		t.Fatalf("run snapshot = %+v", run)
	}
	running, err := s.TransitionRun(ctx, e, run.Ref, RunRunning, "", "")
	if err != nil || running.StartedAt == nil {
		t.Fatalf("running = %+v %v", running, err)
	}
	done, err := s.TransitionRun(ctx, e, run.Ref, RunSucceeded, "", "")
	if err != nil || done.FinishedAt == nil || done.State != RunSucceeded {
		t.Fatalf("done = %+v %v", done, err)
	}
	if _, err := s.TransitionRun(ctx, e, run.Ref, RunCanceled, "", ""); err == nil {
		t.Fatal("terminal run accepted transition")
	}
}
func TestWorkflowPublishRequiresCurrentRevisionAndRunRequiresPublished(t *testing.T) {
	s := NewService(newStore(t), allowAuthorizer{}, nil)
	ctx := context.Background()
	e := testExecution()
	w, err := s.Create(ctx, CreateRequest{Execution: e, OwnerID: 7, Name: "draft", Definition: json.RawMessage(`{"nodes":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartRun(ctx, StartRunRequest{Execution: e, Workflow: w.Ref}); err == nil {
		t.Fatal("draft workflow started")
	}
	if _, err := s.store.PublishVersion(ctx, w.Ref, 1, w.Revision+1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale publish = %v", err)
	}
}
func TestWorkflowAuthorizationIsRechecked(t *testing.T) {
	s := NewService(newStore(t), allowAuthorizer{deny: authz.View}, nil)
	ctx := context.Background()
	e := testExecution()
	w, err := s.Create(ctx, CreateRequest{Execution: e, OwnerID: 7, Name: "auth", Definition: json.RawMessage(`{"nodes":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, e, w.Ref); err == nil {
		t.Fatal("view should be denied")
	}
}
func TestRunTransitionValidation(t *testing.T) {
	r := Run{Ref: resource.Ref{Kind: resource.WorkflowRun, ID: "r"}, Workflow: resource.Ref{Kind: resource.Workflow, ID: "w"}, Version: 1, OwnerID: 7, State: RunPending, Execution: testExecution(), Definition: json.RawMessage(`{"nodes":[]}`), Digest: "bad", Revision: 1, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if r.Validate() == nil {
		t.Fatal("invalid digest accepted")
	}
}
