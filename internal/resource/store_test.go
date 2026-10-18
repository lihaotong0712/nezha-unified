package resource

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newResourceStoreTest(t *testing.T) *GORMStore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	store, err := NewGORMStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestGORMStoreRevisionAndSoftDelete(t *testing.T) {
	store := newResourceStoreTest(t)
	ctx := context.Background()
	ref := Ref{Kind: Workflow, ID: "workflow-1"}
	if err := store.Create(ctx, Metadata{Ref: ref, OwnerID: 7, Revision: 1, State: Active}); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, Metadata{Ref: ref, OwnerID: 7, Revision: 1, State: Active}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create error = %v, want conflict", err)
	}
	updated, err := store.Update(ctx, Metadata{Ref: ref, OwnerID: 7, Revision: 1, State: Disabled}, 1)
	if err != nil || updated.Revision != 2 || updated.State != Disabled {
		t.Fatalf("update = %+v, %v", updated, err)
	}
	if _, err := store.Update(ctx, Metadata{Ref: ref, OwnerID: 7, Revision: 1, State: Active}, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update error = %v, want conflict", err)
	}
	if err := store.Delete(ctx, ref, 2); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, ref)
	if err != nil || got.State != Deleted || got.DeletedAt == nil || got.Revision != 3 || got.Executable() {
		t.Fatalf("deleted metadata = %+v, %v", got, err)
	}
}

func TestGORMStoreListsByOwnerAndState(t *testing.T) {
	store := newResourceStoreTest(t)
	ctx := context.Background()
	for _, metadata := range []Metadata{
		{Ref: Ref{Kind: Workflow, ID: "one"}, OwnerID: 1, Revision: 1, State: Active},
		{Ref: Ref{Kind: Certificate, ID: "two"}, OwnerID: 1, Revision: 1, State: Pending},
		{Ref: Ref{Kind: Workflow, ID: "three"}, OwnerID: 2, Revision: 1, State: Active},
	} {
		if err := store.Create(ctx, metadata); err != nil {
			t.Fatal(err)
		}
	}
	active, err := store.List(ctx, 1, Active)
	if err != nil || len(active) != 1 || active[0].Ref.ID != "one" {
		t.Fatalf("owner/state filter = %+v, %v", active, err)
	}
	all, err := store.List(ctx, 1, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("owner list = %+v, %v", all, err)
	}
}
