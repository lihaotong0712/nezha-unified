package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/dns"
	"github.com/nezhahq/nezha/internal/resource"
	"github.com/nezhahq/nezha/model"
)

type dnsHTTPAuthorizer struct {
	requests []authz.Request
	allowed  bool
}

func (a *dnsHTTPAuthorizer) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	a.requests = append(a.requests, req)
	return authz.Decision{Allowed: a.allowed, PolicyVersion: "dns-http-test"}, nil
}

type dnsHTTPProvider struct {
	record      dns.Record
	lastFilter  dns.RecordFilter
	lastPage    dns.PageRequest
	getCalls    int
	createCalls int
	updateCalls int
	deleteCalls int
}

func (p *dnsHTTPProvider) ListZones(context.Context, dns.PageRequest) (dns.Page[dns.Zone], error) {
	return dns.Page[dns.Zone]{}, nil
}
func (p *dnsHTTPProvider) GetZone(context.Context, dns.ZoneID) (dns.Zone, error) {
	return dns.Zone{}, nil
}
func (p *dnsHTTPProvider) Capabilities(context.Context, dns.Zone) (dns.Capabilities, error) {
	return dns.Capabilities{Features: map[dns.Feature]dns.Support{
		dns.FeatureCreateRecord: {State: dns.SupportAvailable},
		dns.FeatureUpdateRecord: {State: dns.SupportAvailable},
		dns.FeatureDeleteRecord: {State: dns.SupportAvailable},
	}}, nil
}
func (p *dnsHTTPProvider) ListRecords(_ context.Context, _ dns.Zone, filter dns.RecordFilter, page dns.PageRequest) (dns.Page[dns.Record], error) {
	p.lastFilter, p.lastPage = filter, page
	return dns.Page[dns.Record]{Items: []dns.Record{p.record}}, nil
}
func (p *dnsHTTPProvider) GetRecord(context.Context, dns.Zone, dns.RecordID) (dns.Record, error) {
	p.getCalls++
	return p.record, nil
}
func (p *dnsHTTPProvider) CreateRecord(context.Context, dns.Zone, dns.RecordData) (dns.Record, error) {
	p.createCalls++
	return p.record, nil
}
func (p *dnsHTTPProvider) UpdateRecord(context.Context, dns.Zone, dns.Record, dns.RecordData) (dns.Record, error) {
	p.updateCalls++
	return p.record, nil
}
func (p *dnsHTTPProvider) DeleteRecord(context.Context, dns.Zone, dns.Record) error {
	p.deleteCalls++
	return nil
}

func dnsHTTPService(t *testing.T) (*dns.Service, *dnsHTTPProvider, *dnsHTTPAuthorizer) {
	t.Helper()
	store := dns.NewMemoryStore()
	binding := dns.ZoneBinding{
		Ref: resource.Ref{Kind: resource.DNSZone, ID: "zone-local"}, OwnerID: 7,
		Provider: "cloudflare", Remote: dns.Zone{ID: "zone-remote", Name: "example.com."},
		Revision: 1, State: resource.Active,
	}
	require.NoError(t, store.Create(context.Background(), binding))
	authorizer := &dnsHTTPAuthorizer{allowed: true}
	provider := &dnsHTTPProvider{record: dns.Record{ID: "record-1", RecordData: dns.RecordData{Name: "www.example.com.", Type: "A", Value: "192.0.2.1", TTL: dns.TTL{Mode: dns.TTLExplicit, Seconds: 300}}}}
	return dns.NewService(store, authorizer, nil, func(context.Context, authz.Execution, authz.Action, dns.ZoneBinding) (dns.Provider, error) {
		return provider, nil
	}), provider, authorizer
}

func dnsHTTPRouter(t *testing.T, service *dns.Service, token *model.APIToken) *gin.Engine {
	t.Helper()
	SetDNSService(service)
	t.Cleanup(func() { SetDNSService(nil) })
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(model.CtxKeyAuthorizedUser, &model.User{Common: model.Common{ID: 7}, Role: model.RoleMember})
		if token != nil {
			c.Set(apiTokenCtxKey, token)
		}
		c.Next()
	})
	r.GET("/dns/zones", commonHandler(listDNSZones))
	r.GET("/dns/zones/:id/records", commonHandler(listDNSRecords))
	r.GET("/dns/zones/:id/records/:recordID", commonHandler(getDNSRecord))
	r.POST("/dns/zones/:id/records", commonHandler(createDNSRecord))
	r.PATCH("/dns/zones/:id/records/:recordID", commonHandler(updateDNSRecord))
	r.DELETE("/dns/zones/:id/records/:recordID", commonHandler(deleteDNSRecord))
	return r
}

func TestDNSHTTPHandlersUseSessionExecutionAndFilters(t *testing.T) {
	service, provider, authorizer := dnsHTTPService(t)
	r := dnsHTTPRouter(t, service, nil)

	response := httptest.NewRecorder()
	r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/dns/zones/zone-local/records?limit=7&cursor=next&name=www.example.com.&type=a&line=default", nil))
	require.Equal(t, http.StatusOK, response.Code)
	var result model.CommonResponse[dns.Page[dns.Record]]
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.True(t, result.Success)
	require.Len(t, result.Data.Items, 1)
	require.Equal(t, dns.RecordFilter{Name: "www.example.com.", Type: "A", Line: "default"}, provider.lastFilter)
	require.Equal(t, dns.PageRequest{Cursor: "next", Limit: 7}, provider.lastPage)
	require.NotEmpty(t, authorizer.requests)
	require.Equal(t, authz.Session, authorizer.requests[0].Execution.Entry)
	require.Equal(t, authz.User(7), authorizer.requests[0].Execution.Subject)
}

func TestDNSHTTPHandlersReadBeforeUpdateAndDelete(t *testing.T) {
	service, provider, _ := dnsHTTPService(t)
	r := dnsHTTPRouter(t, service, nil)
	body := bytes.NewBufferString(`{"name":"www.example.com.","type":"A","value":"192.0.2.2","ttl":{"mode":"explicit","seconds":300}}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/dns/zones/zone-local/records/record-1", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(response, req)
	require.Equal(t, http.StatusOK, response.Code)
	var updated model.CommonResponse[dns.Record]
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &updated))
	require.True(t, updated.Success)
	require.Equal(t, 1, provider.getCalls)
	require.Equal(t, 1, provider.updateCalls)

	response = httptest.NewRecorder()
	r.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/dns/zones/zone-local/records/record-1", nil))
	require.Equal(t, http.StatusOK, response.Code)
	var deleted model.CommonResponse[map[string]any]
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &deleted))
	require.True(t, deleted.Success)
	require.Equal(t, 2, provider.getCalls)
	require.Equal(t, 1, provider.deleteCalls)
}

func TestDNSHTTPHandlersRejectInvalidIDsAndUnavailableService(t *testing.T) {
	service, _, _ := dnsHTTPService(t)
	r := dnsHTTPRouter(t, service, nil)
	response := httptest.NewRecorder()
	r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/dns/zones/bad%20zone/records", nil))
	var invalid model.CommonResponse[any]
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &invalid))
	require.False(t, invalid.Success)
	require.Contains(t, invalid.Error, "invalid_argument")

	SetDNSService(nil)
	response = httptest.NewRecorder()
	r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/dns/zones", nil))
	var unavailable model.CommonResponse[any]
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &unavailable))
	require.False(t, unavailable.Success)
	require.Contains(t, unavailable.Error, "unavailable")
}

func TestDNSRESTScopeMiddlewareRejectsPATWithoutDNSScope(t *testing.T) {
	r := gin.New()
	tok := &model.APIToken{ScopesCSV: model.ScopeCertificateRead}
	r.Use(func(ctx *gin.Context) { ctx.Set(apiTokenCtxKey, tok); ctx.Next() })
	r.GET("/dns/zones", restScopeMiddleware(model.ScopeDNSRead), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dns/zones", nil)
	r.ServeHTTP(response, req)
	require.Equal(t, http.StatusForbidden, response.Code)
}
