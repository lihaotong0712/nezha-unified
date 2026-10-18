package certificate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
)

// Authorizer is deliberately narrow so certificate code cannot invent a second
// permission system. Every detail and download operation rechecks current
// policy instead of trusting a cached list result.
type Authorizer interface {
	Authorize(context.Context, authz.Request) (authz.Decision, error)
}

type IDGenerator func() (string, error)

type Service struct {
	store      Store
	authorizer Authorizer
	recorder   audit.Recorder
	newID      IDGenerator
	now        func() time.Time
}

func NewService(store Store, authorizer Authorizer, recorder audit.Recorder) *Service {
	return &Service{store: store, authorizer: authorizer, recorder: recorder, newID: newCertificateID, now: time.Now}
}

func newCertificateID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "cert-" + hex.EncodeToString(b[:]), nil
}

type CreateRequest struct {
	Execution      authz.Execution
	OwnerID        uint64
	Name           string
	Source         Source
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

func (s *Service) Create(ctx context.Context, req CreateRequest) (Record, error) {
	if s == nil || s.store == nil || req.OwnerID == 0 || req.Source == "" {
		return Record{}, platformerr.New(platformerr.InvalidArgument, req.Execution.OperationID, nil)
	}
	parsed, err := ParsePEM(req.CertificatePEM, req.PrivateKeyPEM)
	if err != nil {
		return Record{}, platformerr.New(platformerr.InvalidArgument, req.Execution.OperationID, err)
	}
	id, err := s.newID()
	if err != nil {
		return Record{}, platformerr.New(platformerr.Internal, req.Execution.OperationID, err)
	}
	ref := resource.Ref{Kind: resource.Certificate, ID: id}
	decision, err := s.check(ctx, req.Execution, authz.Edit, ref, append(append([]string(nil), parsed.DNSNames...), parsed.IPAddresses...))
	if err != nil {
		return Record{}, err
	}
	now := s.now()
	record := Record{Ref: ref, OwnerID: req.OwnerID, Name: strings.TrimSpace(req.Name), Source: req.Source, Status: statusAt(now, parsed.NotAfter), SerialNumber: parsed.SerialNumber, Subject: parsed.Subject, Issuer: parsed.Issuer, DNSNames: parsed.DNSNames, IPAddresses: parsed.IPAddresses, NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := record.Validate(); err != nil {
		return Record{}, platformerr.New(platformerr.InvalidArgument, req.Execution.OperationID, err)
	}
	if err := s.record(ctx, audit.Event{ID: eventID(req.Execution.OperationID, "create", id), Time: now, Execution: req.Execution, Action: authz.Edit, Resource: ref, Outcome: audit.Requested, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: record.Revision}); err != nil {
		return Record{}, err
	}
	if err := s.store.Create(ctx, record, parsed.CertificatePEM, parsed.PrivateKeyPEM); err != nil {
		_ = s.record(ctx, audit.Event{ID: eventID(req.Execution.OperationID, "create-failed", id), Time: s.now(), Execution: req.Execution, Action: authz.Edit, Resource: ref, Outcome: audit.Failed, Code: platformerr.Conflict, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs})
		return Record{}, platformerr.From(err, req.Execution.OperationID)
	}
	_ = s.record(ctx, audit.Event{ID: eventID(req.Execution.OperationID, "create-succeeded", id), Time: s.now(), Execution: req.Execution, Action: authz.Edit, Resource: ref, Outcome: audit.Succeeded, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: record.Revision})
	return record, nil
}

func (s *Service) Get(ctx context.Context, execution authz.Execution, ref resource.Ref) (Record, error) {
	record, err := s.store.Get(ctx, ref)
	if err != nil {
		return Record{}, platformerr.From(err, execution.OperationID)
	}
	if _, err := s.check(ctx, execution, authz.View, ref, certificateNames(record)); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Service) List(ctx context.Context, execution authz.Execution, ownerID uint64) ([]Record, error) {
	if execution.Subject.Kind == authz.UserPrincipal && execution.Subject.ID != fmt.Sprint(ownerID) {
		// The authorizer still controls delegated access. Owner filtering keeps
		// accidental cross-user list results from becoming a data leak.
		return nil, platformerr.New(platformerr.Forbidden, execution.OperationID, nil)
	}
	records, err := s.store.List(ctx, ownerID)
	if err != nil {
		return nil, platformerr.From(err, execution.OperationID)
	}
	out := make([]Record, 0, len(records))
	for _, record := range records {
		if _, err := s.check(ctx, execution, authz.View, record.Ref, certificateNames(record)); err == nil {
			out = append(out, record)
		}
	}
	return out, nil
}

func (s *Service) Download(ctx context.Context, execution authz.Execution, ref resource.Ref, includePrivate bool) (Bundle, error) {
	record, err := s.store.Get(ctx, ref)
	if err != nil {
		return Bundle{}, platformerr.From(err, execution.OperationID)
	}
	decision, err := s.check(ctx, execution, authz.Download, ref, certificateNames(record))
	if err != nil {
		return Bundle{}, err
	}
	if includePrivate {
		decision, err = s.check(ctx, execution, authz.Reveal, ref, certificateNames(record))
		if err != nil {
			return Bundle{}, err
		}
	}
	now := s.now()
	if err := s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "download", ref.ID), Time: now, Execution: execution, Action: authz.Download, Resource: ref, Outcome: audit.Requested, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: record.Revision}); err != nil {
		return Bundle{}, err
	}
	bundle, err := s.store.Bundle(ctx, ref, includePrivate)
	if err != nil {
		_ = s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "download-failed", ref.ID), Time: s.now(), Execution: execution, Action: authz.Download, Resource: ref, Outcome: audit.Failed, Code: platformerr.From(err, execution.OperationID).Code})
		return Bundle{}, platformerr.From(err, execution.OperationID)
	}
	return bundle, nil
}

func (s *Service) Delete(ctx context.Context, execution authz.Execution, ref resource.Ref) error {
	record, err := s.store.Get(ctx, ref)
	if err != nil {
		return platformerr.From(err, execution.OperationID)
	}
	decision, err := s.check(ctx, execution, authz.Delete, ref, certificateNames(record))
	if err != nil {
		return err
	}
	if err := s.record(ctx, audit.Event{ID: eventID(execution.OperationID, "delete", ref.ID), Time: s.now(), Execution: execution, Action: authz.Delete, Resource: ref, Outcome: audit.Requested, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: record.Revision}); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, ref); err != nil {
		return platformerr.From(err, execution.OperationID)
	}
	return nil
}

func (s *Service) check(ctx context.Context, execution authz.Execution, action authz.Action, ref resource.Ref, names []string) (authz.Decision, error) {
	if s.authorizer == nil {
		return authz.Decision{}, platformerr.New(platformerr.Unavailable, execution.OperationID, nil)
	}
	return authz.Check(ctx, s.authorizer, authz.Request{Execution: execution, Action: action, Resource: ref, CertificateNames: names})
}

func (s *Service) record(ctx context.Context, event audit.Event) error {
	if s.recorder == nil {
		return nil
	}
	if err := s.recorder.Record(ctx, event); err != nil {
		return platformerr.From(err, event.Execution.OperationID)
	}
	return nil
}

func eventID(operation, stage, id string) string {
	return strings.Join([]string{operation, "certificate", stage, id}, ":")
}

func certificateNames(record Record) []string {
	return append(append([]string(nil), record.DNSNames...), record.IPAddresses...)
}

// ImportLegacy accepts the certificate fields used by Certimate exports while
// keeping the import boundary explicit. Callers still receive the same parser,
// SAN and key-matching checks as new uploads.
type LegacyCertificate struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	OwnerID        uint64 `json:"owner_id"`
	CertificatePEM string `json:"certificate"`
	PrivateKeyPEM  string `json:"private_key"`
}

func (s *Service) ImportLegacy(ctx context.Context, execution authz.Execution, legacy LegacyCertificate) (Record, error) {
	if strings.TrimSpace(legacy.ID) != "" {
		ref := resource.Ref{Kind: resource.Certificate, ID: legacy.ID}
		if err := ref.Validate(); err != nil {
			return Record{}, platformerr.New(platformerr.InvalidArgument, execution.OperationID, err)
		}
	}
	return s.Create(ctx, CreateRequest{Execution: execution, OwnerID: legacy.OwnerID, Name: legacy.Name, Source: SourceUpload, CertificatePEM: []byte(legacy.CertificatePEM), PrivateKeyPEM: []byte(legacy.PrivateKeyPEM)})
}
