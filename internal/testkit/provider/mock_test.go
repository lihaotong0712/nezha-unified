package provider

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestMockRecordsVendorRequestAndReturnsJSON(t *testing.T) {
	mock := New(t)
	mock.Handle(http.MethodPost, "/zones/zone-1/records", func(req Request) Response {
		if req.Query.Get("dry_run") != "1" {
			t.Errorf("dry_run = %q, want 1", req.Query.Get("dry_run"))
		}
		return JSONResponse(http.StatusCreated, map[string]any{"id": "record-1"})
	})

	resp, err := http.Post(mock.Server.URL+"/zones/zone-1/records?dry_run=1", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["id"] != "record-1" {
		t.Fatalf("response = %#v", body)
	}
	requests := mock.Requests()
	if len(requests) != 1 || requests[0].Path != "/zones/zone-1/records" {
		t.Fatalf("recorded requests = %#v", requests)
	}
}
