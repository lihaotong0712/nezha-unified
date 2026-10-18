// Package lifecycle defines the explicit Dashboard-owned module lifecycle.
// Module construction must not start goroutines, listeners or schedulers.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Module receives dependencies through its constructor. Init performs storage
// initialization/migrations and registration without starting background work.
// Start launches work and returns promptly. Its context lives until shutdown.
// Stop first rejects new work, then joins/cancels existing work and releases
// resources within its deadline. Stop must tolerate partial Init/Start failure.
type Module interface {
	Name() string
	Init(context.Context) error
	Start(context.Context) error
	Stop(context.Context) error
}

var ErrState = errors.New("invalid module lifecycle state")

// Runtime initializes all modules before starting any, in dependency order.
// Stop runs in reverse order, before singleton DB/RPC/TSDB dependencies close.
// Lifecycle calls are serialized. Modules must not reenter the Runtime.
// A runtime is single-use; construct a new runtime after a startup failure.
type Runtime struct {
	mu             sync.Mutex
	modules        []Module
	initialized    int
	state          state
	cancel         context.CancelFunc
	cleanupTimeout time.Duration
	stopErr        error
}

type state uint8

const (
	newState state = iota
	runningState
	stoppedState
)

// New takes a fixed module list in dependency order and a bounded failure
// cleanup timeout. There is no late registration or implicit global registry.
func New(cleanupTimeout time.Duration, modules ...Module) (*Runtime, error) {
	if cleanupTimeout <= 0 {
		return nil, errors.New("module cleanup timeout must be positive")
	}
	names := make(map[string]bool, len(modules))
	for _, module := range modules {
		if module == nil || module.Name() == "" || names[module.Name()] {
			return nil, errors.New("module names must be nonempty and unique")
		}
		names[module.Name()] = true
	}
	return &Runtime{modules: append([]Module(nil), modules...), cleanupTimeout: cleanupTimeout}, nil
}

func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != newState {
		return ErrState
	}
	workCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	for i, module := range r.modules {
		if err := workCtx.Err(); err != nil {
			return r.startFailed(ctx, err)
		}
		// Include the failing module: Init may have acquired partial resources.
		r.initialized = i + 1
		if err := module.Init(workCtx); err != nil {
			return r.startFailed(ctx, fmt.Errorf("init %s: %w", module.Name(), err))
		}
	}
	for _, module := range r.modules {
		if err := workCtx.Err(); err != nil {
			return r.startFailed(ctx, err)
		}
		if err := module.Start(workCtx); err != nil {
			return r.startFailed(ctx, fmt.Errorf("start %s: %w", module.Name(), err))
		}
	}
	if err := workCtx.Err(); err != nil {
		return r.startFailed(ctx, err)
	}
	r.state = runningState
	return nil
}

func (r *Runtime) startFailed(ctx context.Context, err error) error {
	// A canceled startup context must not suppress cleanup.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.cleanupTimeout)
	defer cancel()
	return errors.Join(err, r.stop(cleanupCtx))
}

// Stop is idempotent, including concurrent calls. A returned error is retained;
// callers must not retry a half-closed module using the same runtime.
// The shutdown context must be independent of the canceled work context.
func (r *Runtime) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stop(ctx)
}

func (r *Runtime) stop(ctx context.Context) error {
	if r.state == stoppedState {
		return r.stopErr
	}
	if r.cancel != nil {
		r.cancel()
	}
	for i := r.initialized - 1; i >= 0; i-- {
		module := r.modules[i]
		if err := module.Stop(ctx); err != nil {
			r.stopErr = errors.Join(r.stopErr, fmt.Errorf("stop %s: %w", module.Name(), err))
		}
	}
	r.state = stoppedState
	return r.stopErr
}
