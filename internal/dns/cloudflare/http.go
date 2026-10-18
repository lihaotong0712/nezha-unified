package cloudflare

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nezhahq/nezha/internal/dns"
)

func (p *Provider) do(ctx context.Context, method, path string, query url.Values, body any, recordID dns.RecordID) (apiEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return apiEnvelope{}, transportError(err, dns.OutcomeNotApplied, recordID)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, requestTimeout)
		defer cancel()
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return apiEnvelope{}, invalid("record body cannot be encoded")
		}
		reader = bytes.NewReader(encoded)
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, path, reader)
	if err != nil {
		return apiEnvelope{}, invalid("API endpoint is invalid")
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	outcome := dns.OutcomeNotApplied
	if method != http.MethodGet {
		outcome = dns.OutcomeUnknown
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return apiEnvelope{}, transportError(err, outcome, recordID)
	}
	defer resp.Body.Close()
	requestID := resp.Header.Get("CF-Ray")
	if requestID == "" {
		requestID = resp.Header.Get("X-Request-ID")
	}
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
	data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil {
		err := transportError(err, outcome, recordID).(*Error)
		err.requestID, err.retryAfter, err.status = requestID, retryAfter, resp.StatusCode
		return apiEnvelope{}, err
	}
	if len(data) > 16<<20 {
		return apiEnvelope{}, &Error{code: dns.ErrorProvider, requestID: requestID, outcome: outcome, recordID: recordID, status: resp.StatusCode}
	}
	var envelope apiEnvelope
	decodeErr := json.Unmarshal(data, &envelope)
	if resp.StatusCode == http.StatusNoContent && method == http.MethodDelete {
		return apiEnvelope{Success: true}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || decodeErr != nil || !envelope.Success || len(envelope.Errors) != 0 {
		code := classifyHTTP(resp.StatusCode)
		vendorCode := ""
		if len(envelope.Errors) > 0 {
			vendorCode = strconv.Itoa(envelope.Errors[0].Code)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				code = classifyVendor(envelope.Errors[0].Code)
			}
		}
		// A valid rejection envelope or a non-timeout 4xx is a definite
		// rejection. 5xx or a malformed successful response stays uncertain.
		if (decodeErr == nil && !envelope.Success && resp.StatusCode < 500) || (resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout) {
			outcome = dns.OutcomeNotApplied
		}
		return apiEnvelope{}, &Error{code: code, vendorCode: vendorCode, requestID: requestID, retryAfter: retryAfter, outcome: outcome, recordID: recordID, status: resp.StatusCode}
	}
	return envelope, nil
}

func transportError(err error, outcome dns.WriteOutcome, recordID dns.RecordID) error {
	code := dns.ErrorUnavailable
	if errors.Is(err, context.Canceled) {
		code = dns.ErrorCanceled
	} else if errors.Is(err, context.DeadlineExceeded) {
		code = dns.ErrorDeadline
	}
	return &Error{code: code, outcome: outcome, recordID: recordID, cause: err}
}

func classifyHTTP(status int) dns.ErrorCode {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return dns.ErrorInvalidArgument
	case http.StatusUnauthorized:
		return dns.ErrorUnauthenticated
	case http.StatusForbidden:
		return dns.ErrorPermission
	case http.StatusNotFound:
		return dns.ErrorNotFound
	case http.StatusConflict:
		return dns.ErrorConflict
	case http.StatusTooManyRequests:
		return dns.ErrorRateLimited
	case http.StatusRequestTimeout:
		return dns.ErrorDeadline
	default:
		if status >= 500 {
			return dns.ErrorUnavailable
		}
		return dns.ErrorProvider
	}
}

func classifyVendor(code int) dns.ErrorCode {
	switch code {
	case 10000, 9103, 9106, 9109:
		return dns.ErrorUnauthenticated
	case 81044:
		return dns.ErrorNotFound
	case 81053, 81057, 81058:
		return dns.ErrorConflict
	case 1015:
		return dns.ErrorRateLimited
	default:
		return dns.ErrorProvider
	}
}

func parseRetryAfter(value string) time.Duration {
	if seconds, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		if delay := time.Until(date); delay > 0 {
			return delay
		}
	}
	return 0
}

type apiEnvelope struct {
	Success    bool            `json:"success"`
	Result     json.RawMessage `json:"result"`
	Errors     []apiError      `json:"errors"`
	ResultInfo *resultInfo     `json:"result_info"`
}

type apiError struct {
	Code int `json:"code"`
}

type resultInfo struct {
	Page       uint32  `json:"page"`
	PerPage    uint32  `json:"per_page"`
	Count      uint32  `json:"count"`
	TotalCount *uint64 `json:"total_count"`
	TotalPages *uint32 `json:"total_pages"`
}

func decodeResult(envelope apiEnvelope, out any) error {
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return errors.New("Cloudflare response has no result")
	}
	return json.Unmarshal(envelope.Result, out)
}

type pageCursor struct {
	Kind     string           `json:"kind"`
	Zone     string           `json:"zone,omitempty"`
	ZoneName string           `json:"zone_name,omitempty"`
	Filter   dns.RecordFilter `json:"filter,omitempty"`
	Limit    uint32           `json:"limit"`
	Page     uint32           `json:"page"`
}

func (p *Provider) pageNumber(page dns.PageRequest, expected pageCursor) (uint32, error) {
	if page.Limit == 0 || page.Limit > maxPageSize {
		return 0, invalid("page limit must be between 1 and 50")
	}
	if page.Cursor == "" {
		return 1, nil
	}
	parts := strings.Split(page.Cursor, ".")
	if len(parts) != 2 {
		return 0, invalid("invalid page cursor")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, invalid("invalid page cursor")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, p.cursorMAC(payload)) {
		return 0, invalid("page cursor belongs to a different account or credential")
	}
	var cursor pageCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.Kind != expected.Kind || cursor.Zone != expected.Zone || cursor.ZoneName != expected.ZoneName || cursor.Filter != expected.Filter || cursor.Page <= 1 || cursor.Limit != page.Limit {
		return 0, invalid("page cursor does not match this request")
	}
	return cursor.Page, nil
}

func (p *Provider) nextCursor(cursor pageCursor, info *resultInfo, rawCount int) (string, error) {
	if info == nil {
		return "", responseError(errors.New("paginated response has no result_info"))
	}
	if (info.Page != 0 && info.Page != cursor.Page) || (info.PerPage != 0 && info.PerPage != cursor.Limit) {
		return "", responseError(errors.New("pagination response does not match request"))
	}
	more := false
	switch {
	case info.TotalPages != nil:
		more = cursor.Page < *info.TotalPages
	case info.TotalCount != nil:
		more = uint64(cursor.Page)*uint64(cursor.Limit) < *info.TotalCount
	default:
		return "", responseError(errors.New("pagination response has no total pages or count"))
	}
	if !more {
		return "", nil
	}
	if cursor.Page == math.MaxUint32 {
		return "", responseError(errors.New("pagination exceeds supported page range"))
	}
	cursor.Page++
	payload, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(p.cursorMAC(payload)), nil
}

func (p *Provider) cursorMAC(payload []byte) []byte {
	// The token is never included in the cursor. The MAC binds a cursor to the
	// endpoint, configured account, credential and all serialized filters.
	key := sha256.Sum256([]byte(p.token))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(p.baseURL + "\x00" + p.accountID + "\x00"))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
