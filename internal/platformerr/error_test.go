package platformerr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestProviderCauseStaysOutOfBoundaryOutput(t *testing.T) {
	cause := errors.New("provider rejected secret=private-token")
	err := New(ProviderFailure, "op-1", cause)
	data, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, output := range []string{string(data), err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(output, "private-token") {
			t.Fatalf("cause leaked: %s", output)
		}
	}
	if !errors.Is(err, cause) || err.HTTPStatus() != http.StatusBadGateway {
		t.Fatal("cause classification or status lost")
	}
}

func TestContextErrorsAndUnknownErrorsAreNormalized(t *testing.T) {
	for _, test := range []struct {
		err    error
		code   Code
		status int
	}{
		{context.Canceled, Canceled, http.StatusRequestTimeout},
		{context.DeadlineExceeded, Timeout, http.StatusGatewayTimeout},
		{errors.New("unsafe provider body"), Internal, http.StatusInternalServerError},
		{&Error{Code: Forbidden, Message: "unsafe message"}, Forbidden, http.StatusForbidden},
		{&Error{Code: "unknown", Message: "unsafe message"}, Internal, http.StatusInternalServerError},
	} {
		got := From(fmt.Errorf("wrapped: %w", test.err), "op-2")
		if got.Code != test.code || got.HTTPStatus() != test.status || strings.Contains(got.Error(), "unsafe") || got.OperationID != "op-2" {
			t.Fatalf("unexpected error: %+v", got)
		}
	}
}
