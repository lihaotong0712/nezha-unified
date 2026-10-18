package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nezhahq/nezha/internal/dns"
	testprovider "github.com/nezhahq/nezha/internal/testkit/provider"
)

func testProvider(t *testing.T) (*Provider, *testprovider.Mock) {
	t.Helper()
	mock := testprovider.New(t)
	return NewProvider(Config{APIToken: "token-for-tests", BaseURL: mock.Server.URL}), mock
}

func envelope(result any, info any) map[string]any {
	response := map[string]any{"success": true, "result": result}
	if info != nil {
		response["result_info"] = info
	}
	return response
}

func TestListZonesUsesOpaquePaginationAndNormalizesNames(t *testing.T) {
	p, mock := testProvider(t)
	mock.Handle(http.MethodGet, "/zones", func(req testprovider.Request) testprovider.Response {
		if req.Query.Get("page") == "1" {
			if req.Query.Get("per_page") != "1" || req.Header.Get("Authorization") != "Bearer token-for-tests" {
				t.Fatalf("request = %#v", req)
			}
			return testprovider.JSONResponse(http.StatusOK, envelope([]any{
				map[string]any{"id": "zone-a", "name": "Example.COM", "type": "full", "status": "active"},
			}, map[string]any{"page": 1, "per_page": 1, "total_pages": 2}))
		}
		if req.Query.Get("page") != "2" {
			t.Fatalf("second page query = %#v", req.Query)
		}
		return testprovider.JSONResponse(http.StatusOK, envelope([]any{
			map[string]any{"id": "zone-b", "name": "other.example", "type": "partial", "status": "pending"},
		}, map[string]any{"page": 2, "per_page": 1, "total_pages": 2}))
	})

	first, err := p.ListZones(context.Background(), dns.PageRequest{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 1 || first.Items[0].Name != "example.com." || first.NextCursor == "" {
		t.Fatalf("first page = %#v", first)
	}
	second, err := p.ListZones(context.Background(), dns.PageRequest{Limit: 1, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].ID != "zone-b" || second.NextCursor != "" {
		t.Fatalf("second page = %#v", second)
	}
}

func TestListRecordsPreservesCloudflareFieldsAndExactFilters(t *testing.T) {
	p, mock := testProvider(t)
	mock.Handle(http.MethodGet, "/zones/zone-a/dns_records", func(req testprovider.Request) testprovider.Response {
		if req.Query.Get("name") != "_acme.example.com" || req.Query.Get("type") != "TXT" {
			t.Fatalf("query = %#v", req.Query)
		}
		proxied := false
		comment := "challenge"
		return testprovider.JSONResponse(http.StatusOK, envelope([]any{
			map[string]any{
				"id": "record-a", "type": "TXT", "name": "_acme.example.com", "content": `"one" "two"`, "ttl": 1,
				"proxied": proxied, "comment": comment, "tags": []string{"managed"},
			},
		}, map[string]any{"page": 1, "per_page": 10, "total_pages": 1}))
	})
	zone := dns.Zone{ID: "zone-a", Name: "example.com."}
	page, err := p.ListRecords(context.Background(), zone, dns.RecordFilter{Name: "_acme.example.com.", Type: "txt"}, dns.PageRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %#v", page.Items)
	}
	record := page.Items[0]
	if record.Value != `"one" "two"` || record.TTL.Mode != dns.TTLAutomatic || record.Proxied == nil || *record.Proxied || record.Comment == nil || *record.Comment != "challenge" {
		t.Fatalf("record = %#v", record)
	}
	if string(record.Extensions["tags"]) != `["managed"]` {
		t.Fatalf("extensions = %#v", record.Extensions)
	}
}

func TestCreateUpdateDeleteUseRecordIDAndPreserveFields(t *testing.T) {
	p, mock := testProvider(t)
	zone := dns.Zone{ID: "zone-a", Name: "example.com."}
	before := dns.Record{ID: "record-a", RecordData: dns.RecordData{
		Name: "www.example.com.", Type: "TXT", Value: `"old" "chunk"`, TTL: dns.TTL{Mode: dns.TTLAutomatic},
		Proxied: boolPtr(false), Comment: stringPtr("old comment"), Extensions: map[string]json.RawMessage{"tags": json.RawMessage(`["managed"]`)},
	}}
	var patchBody map[string]any
	mock.Handle(http.MethodPost, "/zones/zone-a/dns_records", func(req testprovider.Request) testprovider.Response {
		if strings.Contains(string(req.Body), "dns_records/") {
			t.Fatalf("create request used a record path: %s", req.Path)
		}
		var body map[string]any
		if err := json.Unmarshal(req.Body, &body); err != nil {
			t.Fatal(err)
		}
		if body["ttl"] != float64(1) || body["content"] != `"one" "two"` || body["proxied"] != false || body["comment"] != "new comment" {
			t.Fatalf("create body = %#v", body)
		}
		return testprovider.JSONResponse(http.StatusCreated, envelope(map[string]any{
			"id": "created", "type": "TXT", "name": "www.example.com", "content": `"one" "two"`, "ttl": 1, "proxied": false, "comment": "new comment",
		}, nil))
	})
	created, err := p.CreateRecord(context.Background(), zone, dns.RecordData{Name: "www.example.com.", Type: "TXT", Value: `"one" "two"`, TTL: dns.TTL{Mode: dns.TTLAutomatic}, Proxied: boolPtr(false), Comment: stringPtr("new comment")})
	if err != nil || created.ID != "created" || created.Value != `"one" "two"` {
		t.Fatalf("created = %#v, err = %v", created, err)
	}

	mock.Handle(http.MethodGet, "/zones/zone-a/dns_records/record-a", func(req testprovider.Request) testprovider.Response {
		return testprovider.JSONResponse(http.StatusOK, envelope(map[string]any{
			"id": "record-a", "type": "TXT", "name": "www.example.com", "content": `"old" "chunk"`, "ttl": 1, "proxied": false, "comment": "old comment", "tags": []string{"managed"},
		}, nil))
	})
	mock.Handle(http.MethodPatch, "/zones/zone-a/dns_records/record-a", func(req testprovider.Request) testprovider.Response {
		if err := json.Unmarshal(req.Body, &patchBody); err != nil {
			t.Fatal(err)
		}
		return testprovider.JSONResponse(http.StatusOK, envelope(map[string]any{
			"id": "record-a", "type": "TXT", "name": "www.example.com", "content": `"new" "chunk"`, "ttl": 120, "proxied": false, "comment": "updated",
		}, nil))
	})
	after, err := p.UpdateRecord(context.Background(), zone, before, dns.RecordData{Name: "www.example.com.", Type: "TXT", Value: `"new" "chunk"`, TTL: dns.TTL{Mode: dns.TTLExplicit, Seconds: 120}, Proxied: boolPtr(false), Comment: stringPtr("updated"), Extensions: before.Extensions})
	if err != nil || after.ID != before.ID || patchBody["comment"] != "updated" || patchBody["content"] != `"new" "chunk"` {
		t.Fatalf("after = %#v, patch = %#v, err = %v", after, patchBody, err)
	}

	mock.Handle(http.MethodDelete, "/zones/zone-a/dns_records/record-a", func(req testprovider.Request) testprovider.Response {
		return testprovider.JSONResponse(http.StatusOK, envelope(map[string]any{"id": "record-a"}, nil))
	})
	if err := p.DeleteRecord(context.Background(), zone, before); err != nil {
		t.Fatalf("delete = %v", err)
	}
}

func TestErrorsAreClassifiedAndWriteOutcomeIsUnknownOnlyWhenUncertain(t *testing.T) {
	p, mock := testProvider(t)
	zone := dns.Zone{ID: "zone-a", Name: "example.com."}
	for _, test := range []struct {
		name   string
		status int
		code   dns.ErrorCode
		path   string
	}{
		{"rate limit", http.StatusTooManyRequests, dns.ErrorRateLimited, "/zones/zone-a/dns_records"},
		{"permission", http.StatusForbidden, dns.ErrorPermission, "/zones/zone-a/dns_records"},
		{"not found", http.StatusNotFound, dns.ErrorNotFound, "/zones/zone-a/dns_records/missing"},
		{"conflict", http.StatusConflict, dns.ErrorConflict, "/zones/zone-a/dns_records/record-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock.Handle(http.MethodPost, test.path, func(req testprovider.Request) testprovider.Response {
				return testprovider.JSONResponse(test.status, map[string]any{"success": false, "errors": []any{map[string]any{"code": 9}}})
			})
			mock.Handle(http.MethodGet, test.path, func(req testprovider.Request) testprovider.Response {
				return testprovider.JSONResponse(test.status, map[string]any{"success": false, "errors": []any{map[string]any{"code": 9}}})
			})
			var err error
			if test.name == "not found" || test.name == "conflict" {
				_, err = p.GetRecord(context.Background(), zone, "record-a")
			} else {
				_, err = p.CreateRecord(context.Background(), zone, dns.RecordData{Name: "example.com.", Type: "A", Value: "192.0.2.1", TTL: dns.TTL{Mode: dns.TTLExplicit, Seconds: 60}})
			}
			var providerErr dns.ProviderError
			if !errors.As(err, &providerErr) || providerErr.Code() != test.code || providerErr.Outcome() != dns.OutcomeNotApplied {
				t.Fatalf("error = %v, provider = %#v", err, providerErr)
			}
		})
	}
}

func boolPtr(value bool) *bool       { return &value }
func stringPtr(value string) *string { return &value }
