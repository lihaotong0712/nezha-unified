package credential

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/resource"
)

func TestSecretRedactsPointerAndValueAcrossOutputPaths(t *testing.T) {
	secret := NewSecret([]byte("private-token"))
	defer secret.Destroy()
	for _, value := range []any{secret, *secret, Resolved{Version: 3, Type: "provider.token", Secret: secret}} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		outputs := []string{string(data)}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			outputs = append(outputs, fmt.Sprintf(format, value))
		}
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("credential", "value", value)
		outputs = append(outputs, logs.String())
		for _, output := range outputs {
			if strings.Contains(output, "private-token") || strings.Contains(output, "112 114 105 118 97 116 101") || strings.Contains(output, "707269766174652d746f6b656e") {
				t.Fatalf("secret leaked: %s", output)
			}
		}
	}
}

func TestSecretDestroyClearsBorrowedBytesAndDoesNotOwnInput(t *testing.T) {
	input := []byte("private-token")
	secret := NewSecret(input)
	borrowed := secret.Bytes()
	input[0] = 'X'
	if string(borrowed) != "private-token" {
		t.Fatal("secret did not copy the input")
	}
	secret.Destroy()
	secret.Destroy()
	if secret.Bytes() != nil || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("secret was not cleared")
	}
	if input[0] != 'X' {
		t.Fatal("destroy changed caller-owned memory")
	}
}

func TestCredentialUseRequiresTypePurposeConsumerAndTarget(t *testing.T) {
	r := UseRequest{
		Execution:  authz.Execution{Subject: authz.User(1), TriggeredBy: authz.User(1), Entry: authz.Session, OperationID: "op-1"},
		Credential: Ref{ID: "credential1", Version: 3}, ExpectedType: "cloudflare.api_token", Action: authz.Edit,
		Binding: Binding{Purpose: DNSManage, Consumer: resource.Ref{Kind: resource.Workflow, ID: "workflow1"}, Target: resource.Ref{Kind: resource.DNSZone, ID: "zone1"}},
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*UseRequest){
		func(r *UseRequest) { r.ExpectedType = "" },
		func(r *UseRequest) { r.Binding.Purpose = "" },
		func(r *UseRequest) { r.Binding.Consumer = resource.Ref{} },
		func(r *UseRequest) { r.Binding.Target = resource.Ref{} },
		func(r *UseRequest) { r.Credential.ID = "" },
		func(r *UseRequest) { r.Execution.TokenID = 9 },
		func(r *UseRequest) { r.Action = authz.Reveal },
	} {
		candidate := r
		change(&candidate)
		if candidate.Validate() == nil {
			t.Fatal("accepted incomplete credential use request")
		}
	}
}
