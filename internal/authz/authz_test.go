package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
)

type authorizerFunc func(context.Context, Request) (Decision, error)

func (f authorizerFunc) Authorize(ctx context.Context, r Request) (Decision, error) { return f(ctx, r) }

func validRequest() Request {
	return Request{
		Execution: Execution{Subject: User(1), TriggeredBy: User(1), Entry: Session, OperationID: "op-1"},
		Action:    Execute, Resource: resource.Ref{Kind: resource.Workflow, ID: "workflow1"},
	}
}

func requireCode(t *testing.T, err error, code platformerr.Code) {
	t.Helper()
	var boundary *platformerr.Error
	if !errors.As(err, &boundary) || boundary.Code != code {
		t.Fatalf("got %v, want code %s", err, code)
	}
}

func TestCheckFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		a    Authorizer
		code platformerr.Code
	}{
		{"missing service", nil, platformerr.Unavailable},
		{"zero decision", authorizerFunc(func(context.Context, Request) (Decision, error) { return Decision{}, nil }), platformerr.Forbidden},
		{"policy failure", authorizerFunc(func(context.Context, Request) (Decision, error) {
			return Decision{Allowed: true}, errors.New("DB unavailable")
		}), platformerr.Internal},
		{"missing policy version", authorizerFunc(func(context.Context, Request) (Decision, error) { return Decision{Allowed: true}, nil }), platformerr.Unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision, err := Check(context.Background(), test.a, validRequest())
			requireCode(t, err, test.code)
			if decision.Allowed {
				t.Fatal("failed authorization retained an allowed decision")
			}
		})
	}
}

func TestDerivedPATContextAndResolvedNamesReachPolicyEveryTime(t *testing.T) {
	r := validRequest()
	r.Execution.Entry = Recovery
	r.Execution.TokenID = 17
	r.Execution.SourceGrantID = "grant-1"
	r.DNS = []DNSName{
		{Zone: resource.Ref{Kind: resource.DNSZone, ID: "zone1"}, Name: "old.example.com", RecordType: "A"},
		{Zone: resource.Ref{Kind: resource.DNSZone, ID: "zone1"}, Name: "new.example.com", RecordType: "A"},
	}
	r.CertificateNames = []string{"example.com", "*.example.com"}
	calls := 0
	policy := authorizerFunc(func(_ context.Context, got Request) (Decision, error) {
		calls++
		if got.Execution != r.Execution || len(got.DNS) != 2 || len(got.CertificateNames) != 2 {
			t.Fatal("execution restrictions or resolved names were lost")
		}
		return Decision{Allowed: calls == 1, PolicyVersion: "policy-2"}, nil
	})
	if _, err := Check(context.Background(), policy, r); err != nil {
		t.Fatal(err)
	}
	_, err := Check(context.Background(), policy, r)
	requireCode(t, err, platformerr.Forbidden)
	if calls != 2 {
		t.Fatal("authorization was cached across side effects")
	}
}

func TestInvalidAndCanceledRequestsNeverAuthorize(t *testing.T) {
	policy := authorizerFunc(func(context.Context, Request) (Decision, error) {
		t.Fatal("invalid request reached the policy service")
		return Decision{}, nil
	})
	for _, change := range []func(*Request){
		func(r *Request) { r.Execution.Subject = User(0) },
		func(r *Request) { r.Execution.Entry = PAT },
		func(r *Request) { r.Execution.OperationID = "" },
		func(r *Request) { r.Resource.ID = "" },
		func(r *Request) { r.Action = "unknown" },
		func(r *Request) {
			r.Execution.Subject = Principal{Kind: ServicePrincipal, ID: "service1"}
			r.Execution.Entry = Schedule
			r.Execution.TokenID = 1
		},
	} {
		r := validRequest()
		change(&r)
		_, err := Check(context.Background(), policy, r)
		requireCode(t, err, platformerr.InvalidArgument)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Check(ctx, policy, validRequest())
	requireCode(t, err, platformerr.Canceled)
}

func TestCancellationDuringPolicyCheckRejectsAllow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	policy := authorizerFunc(func(context.Context, Request) (Decision, error) {
		cancel()
		return Decision{Allowed: true, PolicyVersion: "policy-1"}, nil
	})
	_, err := Check(ctx, policy, validRequest())
	requireCode(t, err, platformerr.Canceled)
}
