// Package cloudflare implements the internal DNS provider contract against the
// Cloudflare v4 HTTP API. The application selects the account and token and
// performs local user authorization before calling this package.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nezhahq/nezha/internal/dns"
)

const (
	defaultBaseURL = "https://api.cloudflare.com/client/v4"
	maxPageSize    = uint32(50) // A conservative limit supported by both list endpoints.
	requestTimeout = 30 * time.Second
)

// Config binds the adapter to one Cloudflare account and credential. AccountID
// is an optional additional boundary for tokens restricted to a single account;
// set it when a token can access several accounts. BaseURL and HTTPClient allow
// a private API transport or a deterministic test server to be supplied.
type Config struct {
	APIToken   string
	AccountID  string
	BaseURL    string
	HTTPClient *http.Client
}

// Provider implements read and individual-record write operations. It does not
// automatically retry requests, since a failed write can have an unknown result.
type Provider struct {
	token     string
	accountID string
	baseURL   string
	client    *http.Client
}

func New(apiToken string) *Provider { return NewProvider(Config{APIToken: apiToken}) }

func NewProvider(cfg Config) *Provider {
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	return &Provider{token: cfg.APIToken, accountID: cfg.AccountID, baseURL: baseURL, client: client}
}

var (
	_ dns.Provider     = (*Provider)(nil)
	_ dns.RecordWriter = (*Provider)(nil)
)

func (p *Provider) ListZones(ctx context.Context, page dns.PageRequest) (dns.Page[dns.Zone], error) {
	pageNo, err := p.pageNumber(page, pageCursor{Kind: "zones"})
	if err != nil {
		return dns.Page[dns.Zone]{}, err
	}
	query := pageQuery(pageNo, page.Limit)
	if p.accountID != "" {
		query.Set("account.id", p.accountID)
	}
	envelope, err := p.do(ctx, http.MethodGet, p.endpoint("zones"), query, nil, "")
	if err != nil {
		return dns.Page[dns.Zone]{}, err
	}
	var raw []apiZone
	if err := decodeResult(envelope, &raw); err != nil {
		return dns.Page[dns.Zone]{}, responseError(err)
	}
	items := make([]dns.Zone, 0, len(raw))
	for _, item := range raw {
		zone, err := p.zone(item)
		if err != nil {
			return dns.Page[dns.Zone]{}, responseError(err)
		}
		items = append(items, zone)
	}
	next, err := p.nextCursor(pageCursor{Kind: "zones", Limit: page.Limit, Page: pageNo}, envelope.ResultInfo, len(raw))
	if err != nil {
		return dns.Page[dns.Zone]{}, err
	}
	return dns.Page[dns.Zone]{Items: items, NextCursor: next}, nil
}

func (p *Provider) GetZone(ctx context.Context, id dns.ZoneID) (dns.Zone, error) {
	raw, err := p.getZone(ctx, id)
	if err != nil {
		return dns.Zone{}, err
	}
	zone, err := p.zone(raw)
	if err != nil {
		return dns.Zone{}, responseError(err)
	}
	return zone, nil
}

func (p *Provider) getZone(ctx context.Context, id dns.ZoneID) (apiZone, error) {
	if !validID(string(id)) {
		return apiZone{}, invalid("zone ID is required and must be a single path component")
	}
	envelope, err := p.do(ctx, http.MethodGet, p.endpoint("zones", string(id)), nil, nil, "")
	if err != nil {
		return apiZone{}, err
	}
	var raw apiZone
	if err := decodeResult(envelope, &raw); err != nil {
		return apiZone{}, responseError(err)
	}
	if raw.ID != string(id) {
		return apiZone{}, responseError(errors.New("response zone ID differs from requested ID"))
	}
	if _, err := p.zone(raw); err != nil {
		return apiZone{}, responseError(err)
	}
	return raw, nil
}

// Capabilities observes the zone and advertised token permissions. A missing
// permission list leaves write support unknown; it never grants local access.
func (p *Provider) Capabilities(ctx context.Context, zone dns.Zone) (dns.Capabilities, error) {
	if err := validateZone(zone); err != nil {
		return dns.Capabilities{}, err
	}
	raw, err := p.getZone(ctx, zone.ID)
	if err != nil {
		return dns.Capabilities{}, err
	}
	observed, _ := p.zone(raw)
	if observed.Name != zone.Name {
		return dns.Capabilities{}, conflict("")
	}
	write := dns.Support{State: dns.SupportUnknown, Reason: "DNS write permission was not advertised by the zone response"}
	for _, permission := range raw.Permissions {
		if permission == "#dns_records:edit" {
			write = dns.Support{State: dns.SupportAvailable, Reason: "zone response advertises DNS record edit permission"}
			break
		}
	}
	types := make(map[string]dns.Support, len(writableTypes))
	for typ := range writableTypes {
		types[typ] = dns.Support{State: dns.SupportAvailable, Reason: "adapter preserves this record's complete RDATA"}
	}
	minimum, maximum := uint32(60), uint32(86400)
	if raw.Plan.LegacyID == "enterprise" {
		minimum = 30
	}
	if raw.Plan.LegacyID == "" {
		minimum = 0
	}
	var min *uint32
	if minimum != 0 {
		min = &minimum
	}
	return dns.Capabilities{
		Features: map[dns.Feature]dns.Support{
			dns.FeatureCreateRecord: write,
			dns.FeatureUpdateRecord: write,
			dns.FeatureDeleteRecord: write,
			dns.FeatureProxy:        {State: dns.SupportAvailable, Reason: "A, AAAA and CNAME only; proxied records require automatic TTL"},
			dns.FeatureComment:      {State: dns.SupportAvailable},
			dns.FeatureLines:        {State: dns.SupportUnavailable, Reason: "the Cloudflare record API has no line field"},
			dns.FeatureWeight:       {State: dns.SupportUnavailable, Reason: "the Cloudflare record API has no generic record weight"},
			dns.FeatureDisable:      {State: dns.SupportUnavailable, Reason: "the Cloudflare record API has no native disabled state"},
		},
		RecordTypes: types,
		TTL:         dns.TTLLimits{MinSeconds: min, MaxSeconds: &maximum, Automatic: dns.Support{State: dns.SupportAvailable}},
		MaxPageSize: maxPageSize,
	}, nil
}

func (p *Provider) ListRecords(ctx context.Context, zone dns.Zone, filter dns.RecordFilter, page dns.PageRequest) (dns.Page[dns.Record], error) {
	if err := validateZone(zone); err != nil {
		return dns.Page[dns.Record]{}, err
	}
	filter, err := normalizeFilter(filter, zone)
	if err != nil {
		return dns.Page[dns.Record]{}, err
	}
	pageNo, err := p.pageNumber(page, pageCursor{Kind: "records", Zone: string(zone.ID), ZoneName: zone.Name, Filter: filter})
	if err != nil {
		return dns.Page[dns.Record]{}, err
	}
	if filter.Line != "" {
		return dns.Page[dns.Record]{Items: []dns.Record{}}, nil
	}
	query := pageQuery(pageNo, page.Limit)
	if filter.Name != "" {
		query.Set("name", apiName(filter.Name))
	}
	if filter.Type != "" {
		query.Set("type", filter.Type)
	}
	envelope, err := p.do(ctx, http.MethodGet, p.endpoint("zones", string(zone.ID), "dns_records"), query, nil, "")
	if err != nil {
		return dns.Page[dns.Record]{}, err
	}
	var raw []apiRecord
	if err := decodeResult(envelope, &raw); err != nil {
		return dns.Page[dns.Record]{}, responseError(err)
	}
	items := make([]dns.Record, 0, len(raw))
	for _, item := range raw {
		record, err := item.record(zone)
		if err != nil {
			return dns.Page[dns.Record]{}, responseError(err)
		}
		if recordMatches(record, filter) {
			items = append(items, record)
		}
	}
	next, err := p.nextCursor(pageCursor{Kind: "records", Zone: string(zone.ID), ZoneName: zone.Name, Filter: filter, Limit: page.Limit, Page: pageNo}, envelope.ResultInfo, len(raw))
	if err != nil {
		return dns.Page[dns.Record]{}, err
	}
	return dns.Page[dns.Record]{Items: items, NextCursor: next}, nil
}

func (p *Provider) GetRecord(ctx context.Context, zone dns.Zone, id dns.RecordID) (dns.Record, error) {
	if err := validateZone(zone); err != nil {
		return dns.Record{}, err
	}
	if !validID(string(id)) {
		return dns.Record{}, invalid("record ID is required and must be a single path component")
	}
	envelope, err := p.do(ctx, http.MethodGet, p.endpoint("zones", string(zone.ID), "dns_records", string(id)), nil, nil, id)
	if err != nil {
		return dns.Record{}, err
	}
	var raw apiRecord
	if err := decodeResult(envelope, &raw); err != nil {
		return dns.Record{}, responseError(err)
	}
	if raw.ID != string(id) {
		return dns.Record{}, responseError(errors.New("response record ID differs from requested ID"))
	}
	record, err := raw.record(zone)
	if err != nil {
		return dns.Record{}, responseError(err)
	}
	return record, nil
}

func (p *Provider) CreateRecord(ctx context.Context, zone dns.Zone, record dns.RecordData) (dns.Record, error) {
	body, err := recordBody(zone, record, false)
	if err != nil {
		return dns.Record{}, err
	}
	envelope, err := p.do(ctx, http.MethodPost, p.endpoint("zones", string(zone.ID), "dns_records"), nil, body, "")
	if err != nil {
		return dns.Record{}, err
	}
	return p.writtenRecord(ctx, zone, "", envelope)
}

func (p *Provider) UpdateRecord(ctx context.Context, zone dns.Zone, before dns.Record, after dns.RecordData) (dns.Record, error) {
	body, err := recordBody(zone, after, true)
	if err != nil {
		return dns.Record{}, err
	}
	if err := p.checkBefore(ctx, zone, before); err != nil {
		return dns.Record{}, err
	}
	envelope, err := p.do(ctx, http.MethodPatch, p.endpoint("zones", string(zone.ID), "dns_records", string(before.ID)), nil, body, before.ID)
	if err != nil {
		return dns.Record{}, err
	}
	return p.writtenRecord(ctx, zone, before.ID, envelope)
}

func (p *Provider) DeleteRecord(ctx context.Context, zone dns.Zone, before dns.Record) error {
	if err := p.checkBefore(ctx, zone, before); err != nil {
		return err
	}
	envelope, err := p.do(ctx, http.MethodDelete, p.endpoint("zones", string(zone.ID), "dns_records", string(before.ID)), nil, nil, before.ID)
	if err != nil {
		return err
	}
	var deleted struct {
		ID string `json:"id"`
	}
	if len(envelope.Result) != 0 && string(envelope.Result) != "null" {
		if err := json.Unmarshal(envelope.Result, &deleted); err != nil || (deleted.ID != "" && deleted.ID != string(before.ID)) {
			return writeResponseError(errors.New("invalid delete response"), dns.OutcomeApplied, before.ID)
		}
	}
	return nil
}

func (p *Provider) checkBefore(ctx context.Context, zone dns.Zone, before dns.Record) error {
	current, err := p.GetRecord(ctx, zone, before.ID)
	if err != nil {
		return err
	}
	if !recordsEqual(current, before) {
		return conflict(before.ID)
	}
	return nil
}

func (p *Provider) writtenRecord(ctx context.Context, zone dns.Zone, knownID dns.RecordID, envelope apiEnvelope) (dns.Record, error) {
	var raw apiRecord
	if err := decodeResult(envelope, &raw); err != nil {
		return dns.Record{}, writeResponseError(err, dns.OutcomeApplied, knownID)
	}
	if raw.ID != "" {
		if knownID != "" && string(knownID) != raw.ID {
			return dns.Record{}, writeResponseError(errors.New("response record ID differs from updated ID"), dns.OutcomeApplied, knownID)
		}
		knownID = dns.RecordID(raw.ID)
	}
	record, err := raw.record(zone)
	if err == nil {
		return record, nil
	}
	if knownID != "" {
		// The vendor acknowledged the mutation; a failed read-back must retain
		// its applied outcome and known ID rather than suggesting a retry.
		record, err = p.GetRecord(ctx, zone, knownID)
		if err == nil {
			return record, nil
		}
	}
	return dns.Record{}, writeResponseError(err, dns.OutcomeApplied, knownID)
}

func (p *Provider) endpoint(parts ...string) string {
	escaped := make([]string, len(parts))
	for i, part := range parts {
		escaped[i] = url.PathEscape(part)
	}
	return p.baseURL + "/" + strings.Join(escaped, "/")
}

func pageQuery(page, limit uint32) url.Values {
	return url.Values{"page": {strconv.FormatUint(uint64(page), 10)}, "per_page": {strconv.FormatUint(uint64(limit), 10)}}
}

type apiZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Status      string   `json:"status"`
	Permissions []string `json:"permissions"`
	Account     struct {
		ID string `json:"id"`
	} `json:"account"`
	Plan struct {
		LegacyID string `json:"legacy_id"`
	} `json:"plan"`
}

func (p *Provider) zone(raw apiZone) (dns.Zone, error) {
	if !validID(raw.ID) {
		return dns.Zone{}, errors.New("zone has no valid ID")
	}
	if p.accountID != "" && raw.Account.ID != p.accountID {
		return dns.Zone{}, errors.New("zone response does not belong to configured account")
	}
	name, err := normalizeFQDN(raw.Name)
	if err != nil {
		return dns.Zone{}, err
	}
	return dns.Zone{ID: dns.ZoneID(raw.ID), Name: name, AccessMode: raw.Type, Status: raw.Status}, nil
}

func conflict(id dns.RecordID) error {
	return &Error{code: dns.ErrorConflict, outcome: dns.OutcomeNotApplied, recordID: id}
}

func invalid(message string) error {
	return &Error{code: dns.ErrorInvalidArgument, outcome: dns.OutcomeNotApplied, message: message}
}

func unsupported(message string) error {
	return &Error{code: dns.ErrorUnsupported, outcome: dns.OutcomeNotApplied, message: message}
}

func validID(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.ContainsAny(id, "/\\?%#\r\n\t ")
}

// Kept separate from the vendor error message: only static local diagnostics
// can be returned by the adapter's Error() method.
func responseError(cause error) error {
	return &Error{code: dns.ErrorProvider, outcome: dns.OutcomeNotApplied, cause: cause}
}

func writeResponseError(cause error, outcome dns.WriteOutcome, id dns.RecordID) error {
	var providerErr dns.ProviderError
	if errors.As(cause, &providerErr) {
		return &Error{code: providerErr.Code(), vendorCode: providerErr.VendorCode(), requestID: providerErr.RequestID(), retryAfter: providerErr.RetryAfter(), outcome: outcome, recordID: id, cause: cause}
	}
	return &Error{code: dns.ErrorProvider, outcome: outcome, recordID: id, cause: cause}
}

// Error implements dns.ProviderError without exposing tokens, request bodies,
// raw vendor messages, or RDATA through Error().
type Error struct {
	code       dns.ErrorCode
	vendorCode string
	requestID  string
	retryAfter time.Duration
	outcome    dns.WriteOutcome
	recordID   dns.RecordID
	status     int
	message    string
	cause      error
}

func (e *Error) Error() string {
	message := fmt.Sprintf("cloudflare: %s", e.code)
	if e.status != 0 {
		message += fmt.Sprintf(" (HTTP %d)", e.status)
	}
	if e.message != "" {
		message += ": " + e.message
	}
	return message
}
func (e *Error) Unwrap() error             { return e.cause }
func (e *Error) Code() dns.ErrorCode       { return e.code }
func (e *Error) VendorCode() string        { return e.vendorCode }
func (e *Error) RequestID() string         { return e.requestID }
func (e *Error) RetryAfter() time.Duration { return e.retryAfter }
func (e *Error) Outcome() dns.WriteOutcome { return e.outcome }
func (e *Error) RecordID() dns.RecordID    { return e.recordID }
