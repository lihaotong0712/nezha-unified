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

func TestCreateRollsBackWorkflowWhenInitialVersionFails(t *testing.T) {
	s := NewService(newStore(t), allowAuthorizer{}, nil)
	if err := s.store.(*GORMStore).db.Exec(`CREATE TRIGGER fail_workflow_version_insert BEFORE INSERT ON platform_workflow_versions BEGIN SELECT RAISE(ABORT, 'version insert failed'); END`).Error; err != nil {
		t.Fatal(err)
	}
	_, err := s.Create(context.Background(), CreateRequest{Execution: testExecution(), OwnerID: 7, Name: "rollback", Definition: json.RawMessage(`{"nodes":[]}`)})
	if err == nil {
		t.Fatal("create succeeded despite version insert failure")
	}
	var workflows, versions int64
	db := s.store.(*GORMStore).db
	if err := db.Model(&workflowRow{}).Count(&workflows).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&versionRow{}).Count(&versions).Error; err != nil {
		t.Fatal(err)
	}
	if workflows != 0 || versions != 0 {
		t.Fatalf("transaction left rows: workflows=%d versions=%d", workflows, versions)
	}
}

func TestSaveVersionAtomicRollsBackRevisionAndRejectsStaleWriter(t *testing.T) {
	s := NewService(newStore(t), allowAuthorizer{}, nil)
	ctx := context.Background()
	e := testExecution()
	w, err := s.Create(ctx, CreateRequest{Execution: e, OwnerID: 7, Name: "versions", Definition: json.RawMessage(`{"nodes":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	store := s.store.(*GORMStore)
	if err := store.db.Exec(`CREATE TRIGGER fail_workflow_version_insert BEFORE INSERT ON platform_workflow_versions BEGIN SELECT RAISE(ABORT, 'version insert failed'); END`).Error; err != nil {
		t.Fatal(err)
	}
	_, err = s.SaveVersion(ctx, e, w.Ref, json.RawMessage(`{"nodes":[{"type":"issue"}]}`))
	if err == nil {
		t.Fatal("save succeeded despite version insert failure")
	}
	current, err := store.Get(ctx, w.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != w.Revision {
		t.Fatalf("revision changed after rollback: got %d want %d", current.Revision, w.Revision)
	}
	versions, err := store.ListVersions(ctx, w.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Fatalf("version rows after rollback = %d", len(versions))
	}
	if err := store.db.Exec(`DROP TRIGGER fail_workflow_version_insert`).Error; err != nil {
		t.Fatal(err)
	}
	first, err := store.SaveVersionAtomic(ctx, current, Version{Workflow: w.Ref, State: VersionDraft, Definition: json.RawMessage(`{"nodes":[{"type":"issue"}]}`), Digest: mustDigest(t, json.RawMessage(`{"nodes":[{"type":"issue"}]}`)), CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if first.Number != 2 {
		t.Fatalf("first new version number = %d", first.Number)
	}
	if _, err := store.SaveVersionAtomic(ctx, current, Version{Workflow: w.Ref, State: VersionDraft, Definition: json.RawMessage(`{"nodes":[{"type":"issue"}]}`), Digest: first.Digest, CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale writer error = %v", err)
	}
	current, err = store.Get(ctx, w.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != w.Revision+1 {
		t.Fatalf("revision after successful save = %d want %d", current.Revision, w.Revision+1)
	}
}

func mustDigest(t *testing.T, definition []byte) string {
	t.Helper()
	_, digest, err := ValidateDefinition(definition)
	if err != nil {
		t.Fatal(err)
	}
	return digest
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

func TestPublishIsIdempotentAndRunRevisionIsOptimistic(t *testing.T) {
	s := NewService(newStore(t), allowAuthorizer{}, nil)
	ctx := context.Background()
	e := testExecution()
	w, err := s.Create(ctx, CreateRequest{Execution: e, OwnerID: 7, Name: "publish", Definition: json.RawMessage(`{"nodes":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	store := s.store.(*GORMStore)
	published, err := store.PublishVersion(ctx, w.Ref, 1, w.Revision)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.PublishVersion(ctx, w.Ref, 1, published.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if again.Revision != published.Revision || again.CurrentVersion != 1 {
		t.Fatalf("idempotent publish = %+v, first = %+v", again, published)
	}
	if _, err := store.PublishVersion(ctx, w.Ref, 1, w.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale publish = %v", err)
	}

	run, err := s.StartRun(ctx, StartRunRequest{Execution: e, Workflow: w.Ref})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.GetRun(ctx, run.Ref)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	first.State = RunRunning
	first.UpdatedAt = time.Now().UTC()
	if _, err := store.UpdateRun(ctx, first, first.Revision); err != nil {
		t.Fatal(err)
	}
	second.State = RunCanceled
	second.UpdatedAt = time.Now().UTC()
	if _, err := store.UpdateRun(ctx, second, second.Revision); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale run update = %v", err)
	}
}

func TestRunKeepsImmutableDefinitionAcrossVersionPublish(t *testing.T) {
	s := NewService(newStore(t), allowAuthorizer{}, nil)
	ctx := context.Background()
	e := testExecution()
	w, err := s.Create(ctx, CreateRequest{Execution: e, OwnerID: 7, Name: "snapshot", Definition: json.RawMessage(`{"nodes":[{"type":"first"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, e, w.Ref, 1); err != nil {
		t.Fatal(err)
	}
	run, err := s.StartRun(ctx, StartRunRequest{Execution: e, Workflow: w.Ref})
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), run.Definition...)
	current, err := s.Get(ctx, e, w.Ref)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.SaveVersion(ctx, e, w.Ref, json.RawMessage(`{"nodes":[{"type":"second"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, e, w.Ref, v2.Number); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetRun(ctx, e, run.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Version != current.CurrentVersion || string(stored.Definition) != string(before) || stored.Digest != run.Digest {
		t.Fatalf("run snapshot changed: got version=%d definition=%s digest=%s", stored.Version, stored.Definition, stored.Digest)
	}
}
