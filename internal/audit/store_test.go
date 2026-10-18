package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newAuditRecorderTest(t *testing.T) *GORMRecorder {
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
	recorder, err := NewGORMRecorder(db)
	if err != nil {
		t.Fatal(err)
	}
	return recorder
}

func testEvent(id string, outcome Outcome) Event {
	return Event{ID: id, Time: time.Unix(100, 0).UTC(), Execution: authz.Execution{Subject: authz.User(7), TriggeredBy: authz.User(7), Entry: authz.Session, OperationID: "operation-1"}, Action: authz.Execute, Resource: resource.Ref{Kind: resource.Workflow, ID: "workflow-1"}, Outcome: outcome, Code: platformerr.Forbidden, PolicyVersion: "policy-1", GrantIDs: []string{"grant-b", "grant-a"}, ResourceRevision: 3}
}

func TestGORMRecorderDeduplicatesExactEventAndRejectsIDReuse(t *testing.T) {
	recorder := newAuditRecorderTest(t)
	ctx := context.Background()
	event := testEvent("event-1", Requested)
	if err := recorder.Record(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(ctx, event); err != nil {
		t.Fatalf("exact replay = %v, want idempotent success", err)
	}
	changed := event
	changed.Outcome = Succeeded
	if err := recorder.Record(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("same ID with changed content = %v, want conflict", err)
	}
	got, err := recorder.Get(ctx, event.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != event.ID || got.Outcome != Requested || got.Execution.OperationID != event.Execution.OperationID || len(got.GrantIDs) != 2 {
		t.Fatalf("persisted event = %+v", got)
	}
}

func TestGORMRecorderCorrelatesOperationAttempts(t *testing.T) {
	recorder := newAuditRecorderTest(t)
	first := testEvent("event-1", Requested)
	second := testEvent("event-2", Succeeded)
	second.Time = second.Time.Add(time.Second)
	if err := recorder.Record(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	events, err := recorder.ListByOperation(context.Background(), "operation-1")
	if err != nil || len(events) != 2 || events[0].Outcome != Requested || events[1].Outcome != Succeeded {
		t.Fatalf("operation events = %+v, %v", events, err)
	}
	if _, err := recorder.ListByOperation(context.Background(), " "); err == nil {
		t.Fatal("empty operation ID accepted")
	}
}
