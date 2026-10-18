package workflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/nezhahq/nezha/internal/audit"
	"github.com/nezhahq/nezha/internal/authz"
	"github.com/nezhahq/nezha/internal/platformerr"
	"github.com/nezhahq/nezha/internal/resource"
)

type Authorizer interface {
	Authorize(context.Context, authz.Request) (authz.Decision, error)
}
type IDGenerator func(string) (string, error)

type Service struct {
	store      Store
	authorizer Authorizer
	recorder   audit.Recorder
	newID      IDGenerator
	now        func() time.Time
}

func NewService(store Store, authorizer Authorizer, recorder audit.Recorder) *Service {
	return &Service{store: store, authorizer: authorizer, recorder: recorder, newID: randomID, now: time.Now}
}

func randomID(prefix string) (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func (s *Service) check(ctx context.Context, e authz.Execution, a authz.Action, ref resource.Ref) (authz.Decision, error) {
	if s == nil || s.store == nil || s.authorizer == nil {
		return authz.Decision{}, platformerr.New(platformerr.Unavailable, e.OperationID, nil)
	}
	return authz.Check(ctx, s.authorizer, authz.Request{Execution: e, Action: a, Resource: ref})
}
func (s *Service) record(ctx context.Context, e audit.Event) error {
	if s.recorder == nil {
		return nil
	}
	if err := s.recorder.Record(ctx, e); err != nil {
		return platformerr.From(err, e.Execution.OperationID)
	}
	return nil
}
func auditID(op, stage, id string) string {
	return strings.Join([]string{op, "workflow", stage, id}, ":")
}

func (s *Service) Create(ctx context.Context, req CreateRequest) (Workflow, error) {
	if s == nil || s.store == nil || req.OwnerID == 0 || strings.TrimSpace(req.Name) == "" {
		return Workflow{}, platformerr.New(platformerr.InvalidArgument, req.Execution.OperationID, nil)
	}
	definition, digest, err := ValidateDefinition(req.Definition)
	if err != nil {
		return Workflow{}, platformerr.New(platformerr.InvalidArgument, req.Execution.OperationID, err)
	}
	id, err := s.newID("workflow-")
	if err != nil {
		return Workflow{}, platformerr.New(platformerr.Internal, req.Execution.OperationID, err)
	}
	ref := resource.Ref{Kind: resource.Workflow, ID: id}
	decision, err := s.check(ctx, req.Execution, authz.Edit, ref)
	if err != nil {
		return Workflow{}, err
	}
	now := s.now().UTC()
	w := Workflow{Ref: ref, OwnerID: req.OwnerID, Name: strings.TrimSpace(req.Name), State: StateDraft, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := w.Validate(); err != nil {
		return Workflow{}, platformerr.New(platformerr.InvalidArgument, req.Execution.OperationID, err)
	}
	v := Version{Workflow: ref, Number: 1, State: VersionDraft, Definition: definition, Digest: digest, CreatedAt: now}
	if err := v.Validate(); err != nil {
		return Workflow{}, platformerr.New(platformerr.InvalidArgument, req.Execution.OperationID, err)
	}
	if err := s.record(ctx, audit.Event{ID: auditID(req.Execution.OperationID, "create", id), Time: now, Execution: req.Execution, Action: authz.Edit, Resource: ref, Outcome: audit.Requested, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: w.Revision}); err != nil {
		return Workflow{}, err
	}
	if err := s.store.Create(ctx, w); err != nil {
		return Workflow{}, platformerr.From(err, req.Execution.OperationID)
	}
	if err := s.store.CreateVersion(ctx, v); err != nil {
		return Workflow{}, platformerr.From(err, req.Execution.OperationID)
	}
	_ = s.record(ctx, audit.Event{ID: auditID(req.Execution.OperationID, "create-succeeded", id), Time: s.now(), Execution: req.Execution, Action: authz.Edit, Resource: ref, Outcome: audit.Succeeded, PolicyVersion: decision.PolicyVersion, GrantIDs: decision.GrantIDs, ResourceRevision: w.Revision})
	return w, nil
}

func (s *Service) Get(ctx context.Context, e authz.Execution, ref resource.Ref) (Workflow, error) {
	w, err := s.store.Get(ctx, ref)
	if err != nil {
		return Workflow{}, platformerr.From(err, e.OperationID)
	}
	if _, err = s.check(ctx, e, authz.View, ref); err != nil {
		return Workflow{}, err
	}
	return w, nil
}
func (s *Service) List(ctx context.Context, e authz.Execution, owner uint64) ([]Workflow, error) {
	rows, err := s.store.List(ctx, owner)
	if err != nil {
		return nil, platformerr.From(err, e.OperationID)
	}
	out := make([]Workflow, 0, len(rows))
	for _, w := range rows {
		if _, err := s.check(ctx, e, authz.View, w.Ref); err == nil {
			out = append(out, w)
		}
	}
	return out, nil
}
func (s *Service) Versions(ctx context.Context, e authz.Execution, ref resource.Ref) ([]Version, error) {
	if _, err := s.check(ctx, e, authz.View, ref); err != nil {
		return nil, err
	}
	rows, err := s.store.ListVersions(ctx, ref)
	if err != nil {
		return nil, platformerr.From(err, e.OperationID)
	}
	return rows, nil
}

func (s *Service) SaveVersion(ctx context.Context, e authz.Execution, ref resource.Ref, definition []byte) (Version, error) {
	w, err := s.store.Get(ctx, ref)
	if err != nil {
		return Version{}, platformerr.From(err, e.OperationID)
	}
	if _, err = s.check(ctx, e, authz.Edit, ref); err != nil {
		return Version{}, err
	}
	normalized, digest, err := ValidateDefinition(definition)
	if err != nil {
		return Version{}, platformerr.New(platformerr.InvalidArgument, e.OperationID, err)
	}
	versions, err := s.store.ListVersions(ctx, ref)
	if err != nil {
		return Version{}, platformerr.From(err, e.OperationID)
	}
	n := uint64(len(versions) + 1)
	now := s.now().UTC()
	v := Version{Workflow: ref, Number: n, State: VersionDraft, Definition: normalized, Digest: digest, CreatedAt: now}
	if err := s.store.CreateVersion(ctx, v); err != nil {
		return Version{}, platformerr.From(err, e.OperationID)
	}
	w.UpdatedAt = now
	w.Revision++
	if _, err := s.store.Update(ctx, w, w.Revision-1); err != nil {
		return Version{}, platformerr.From(err, e.OperationID)
	}
	return v, nil
}
func (s *Service) Publish(ctx context.Context, e authz.Execution, ref resource.Ref, n uint64) (Workflow, error) {
	if _, err := s.check(ctx, e, authz.Edit, ref); err != nil {
		return Workflow{}, err
	}
	w, err := s.store.Get(ctx, ref)
	if err != nil {
		return Workflow{}, platformerr.From(err, e.OperationID)
	}
	out, err := s.store.PublishVersion(ctx, ref, n, w.Revision)
	if err != nil {
		return Workflow{}, platformerr.From(err, e.OperationID)
	}
	return out, nil
}
func (s *Service) Delete(ctx context.Context, e authz.Execution, ref resource.Ref) error {
	w, err := s.store.Get(ctx, ref)
	if err != nil {
		return platformerr.From(err, e.OperationID)
	}
	d, err := s.check(ctx, e, authz.Delete, ref)
	if err != nil {
		return err
	}
	if err := s.record(ctx, audit.Event{ID: auditID(e.OperationID, "delete", ref.ID), Time: s.now(), Execution: e, Action: authz.Delete, Resource: ref, Outcome: audit.Requested, PolicyVersion: d.PolicyVersion, GrantIDs: d.GrantIDs, ResourceRevision: w.Revision}); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, ref, w.Revision); err != nil {
		return platformerr.From(err, e.OperationID)
	}
	_ = s.record(ctx, audit.Event{ID: auditID(e.OperationID, "delete-succeeded", ref.ID), Time: s.now(), Execution: e, Action: authz.Delete, Resource: ref, Outcome: audit.Succeeded, PolicyVersion: d.PolicyVersion, GrantIDs: d.GrantIDs, ResourceRevision: w.Revision + 1})
	return nil
}

func (s *Service) StartRun(ctx context.Context, req StartRunRequest) (Run, error) {
	w, err := s.store.Get(ctx, req.Workflow)
	if err != nil {
		return Run{}, platformerr.From(err, req.Execution.OperationID)
	}
	d, err := s.check(ctx, req.Execution, authz.Execute, req.Workflow)
	if err != nil {
		return Run{}, err
	}
	if w.State != StateActive || w.CurrentVersion == 0 {
		return Run{}, platformerr.New(platformerr.Conflict, req.Execution.OperationID, ErrDisabled)
	}
	v, err := s.store.GetVersion(ctx, req.Workflow, w.CurrentVersion)
	if err != nil {
		return Run{}, platformerr.From(err, req.Execution.OperationID)
	}
	id, err := s.newID("run-")
	if err != nil {
		return Run{}, platformerr.New(platformerr.Internal, req.Execution.OperationID, err)
	}
	now := s.now().UTC()
	r := Run{Ref: resource.Ref{Kind: resource.WorkflowRun, ID: id}, Workflow: req.Workflow, Version: v.Number, OwnerID: w.OwnerID, State: RunPending, Execution: req.Execution, Definition: append([]byte(nil), v.Definition...), Digest: v.Digest, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := r.Validate(); err != nil {
		return Run{}, platformerr.New(platformerr.InvalidArgument, req.Execution.OperationID, err)
	}
	if err := s.record(ctx, audit.Event{ID: auditID(req.Execution.OperationID, "run", id), Time: now, Execution: req.Execution, Action: authz.Execute, Resource: req.Workflow, Outcome: audit.Requested, PolicyVersion: d.PolicyVersion, GrantIDs: d.GrantIDs, ResourceRevision: w.Revision}); err != nil {
		return Run{}, err
	}
	if err := s.store.CreateRun(ctx, r); err != nil {
		return Run{}, platformerr.From(err, req.Execution.OperationID)
	}
	return r, nil
}
func (s *Service) GetRun(ctx context.Context, e authz.Execution, ref resource.Ref) (Run, error) {
	r, err := s.store.GetRun(ctx, ref)
	if err != nil {
		return Run{}, platformerr.From(err, e.OperationID)
	}
	if _, err = s.check(ctx, e, authz.View, r.Workflow); err != nil {
		return Run{}, err
	}
	return r, nil
}
func (s *Service) ListRuns(ctx context.Context, e authz.Execution, workflow resource.Ref) ([]Run, error) {
	if _, err := s.check(ctx, e, authz.View, workflow); err != nil {
		return nil, err
	}
	rows, err := s.store.ListRuns(ctx, workflow)
	if err != nil {
		return nil, platformerr.From(err, e.OperationID)
	}
	return rows, nil
}
func (s *Service) TransitionRun(ctx context.Context, e authz.Execution, ref resource.Ref, to RunState, code, message string) (Run, error) {
	r, err := s.store.GetRun(ctx, ref)
	if err != nil {
		return Run{}, platformerr.From(err, e.OperationID)
	}
	if _, err = s.check(ctx, e, authz.Execute, r.Workflow); err != nil {
		return Run{}, err
	}
	if !nextRunState(r.State, to) {
		return Run{}, platformerr.New(platformerr.Conflict, e.OperationID, ErrInvalidRunTransition)
	}
	now := s.now().UTC()
	r.State = to
	r.ErrorCode = code
	r.ErrorMessage = message
	if to == RunRunning {
		r.StartedAt = &now
	}
	if to == RunSucceeded || to == RunFailed || to == RunCanceled {
		r.FinishedAt = &now
	}
	out, err := s.store.UpdateRun(ctx, r, r.Revision)
	if err != nil {
		return Run{}, platformerr.From(err, e.OperationID)
	}
	outcome := audit.Succeeded
	if to == RunFailed {
		outcome = audit.Failed
	}
	if to == RunCanceled {
		outcome = audit.Canceled
	}
	_ = s.record(ctx, audit.Event{ID: auditID(e.OperationID, "run-"+string(to), ref.ID), Time: now, Execution: e, Action: authz.Execute, Resource: r.Workflow, Outcome: outcome, Code: platformerr.Code(code), ResourceRevision: out.Revision})
	return out, nil
}
