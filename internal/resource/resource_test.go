package resource

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func TestReferenceIdentityAndJSONRoundTrip(t *testing.T) {
	server, err := Native(Server, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []Ref{server, {Kind: Certificate, ID: "opaque007"}, {Kind: Credential, ID: "opaque007"}} {
		data, err := json.Marshal(ref)
		if err != nil {
			t.Fatal(err)
		}
		var got Ref
		if err := json.Unmarshal(data, &got); err != nil || got != ref || got.Validate() != nil {
			t.Fatalf("reference changed: %s -> %+v, %v", data, got, err)
		}
	}
	if (Ref{Kind: Certificate, ID: "opaque007"}) == (Ref{Kind: Credential, ID: "opaque007"}) {
		t.Fatal("different resource kinds collided")
	}
}

func TestRejectAmbiguousAndMissingReferences(t *testing.T) {
	for _, ref := range []Ref{
		{}, {Kind: "unknown", ID: "1"}, {Kind: User, ID: "0"},
		{Kind: Server, ID: "01"}, {Kind: Server, ID: "+1"},
		{Kind: User, ID: "18446744073709551616"},
		{Kind: Certificate, ID: ""}, {Kind: Credential, ID: " id"},
		{Kind: Credential, ID: "a:b"}, {Kind: DNSZone, ID: "a/b"},
		{Kind: Workflow, ID: "a\nb"}, {Kind: Workflow, ID: "a\u2003b"},
		{Kind: Certificate, ID: string([]byte{0xff})},
	} {
		if ref.Validate() == nil {
			t.Errorf("accepted invalid reference: %+v", ref)
		}
	}
	if _, err := Native(Credential, 1); err == nil {
		t.Fatal("native conversion accepted an opaque resource kind")
	}
}

func TestOnlyActiveOwnedResourcesAreExecutable(t *testing.T) {
	valid := Metadata{Ref: Ref{Kind: Workflow, ID: "workflow1"}, OwnerID: 1, Revision: 1, State: Active}
	if !valid.Executable() {
		t.Fatal("active resource rejected")
	}
	for _, state := range []State{"", Pending, Disabled, Deleted} {
		candidate := valid
		candidate.State = state
		if candidate.Executable() {
			t.Errorf("state %q can execute", state)
		}
	}
	for _, change := range []func(*Metadata){
		func(m *Metadata) { m.OwnerID = 0 },
		func(m *Metadata) { m.Revision = 0 },
		func(m *Metadata) { now := time.Now(); m.DeletedAt = &now },
		func(m *Metadata) { m.Ref.ID = "" },
	} {
		candidate := valid
		change(&candidate)
		if candidate.Executable() {
			t.Fatal("incomplete/deleted resource can execute")
		}
	}
}
