package dns

import (
	"context"
	"errors"
	"testing"

	"github.com/nezhahq/nezha/internal/resource"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGORMStorePersistsZoneBindings(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:dns-bindings?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewGORMStore(db)
	if err != nil {
		t.Fatal(err)
	}
	binding := testBinding()
	if err := store.Create(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), binding.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Remote.ID != binding.Remote.ID || got.Remote.Name != binding.Remote.Name || got.OwnerID != binding.OwnerID {
		t.Fatalf("binding=%+v", got)
	}
	list, err := store.List(context.Background(), binding.OwnerID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if err := store.Create(context.Background(), binding); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("duplicate err=%v", err)
	}
}

func TestGORMStoreValidatesReferences(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:dns-bindings-invalid?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewGORMStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), resource.Ref{Kind: resource.Certificate, ID: "x"}); err == nil {
		t.Fatal("invalid kind accepted")
	}
}
