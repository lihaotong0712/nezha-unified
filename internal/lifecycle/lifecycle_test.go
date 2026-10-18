package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type testModule struct {
	name     string
	events   *[]string
	initErr  error
	startErr error
	stopErr  error
	workCtx  context.Context
	onInit   func()
	onStop   func(context.Context)
}

func (m *testModule) Name() string { return m.name }
func (m *testModule) Init(context.Context) error {
	*m.events = append(*m.events, "init:"+m.name)
	if m.onInit != nil {
		m.onInit()
	}
	return m.initErr
}
func (m *testModule) Start(ctx context.Context) error {
	*m.events = append(*m.events, "start:"+m.name)
	m.workCtx = ctx
	return m.startErr
}
func (m *testModule) Stop(ctx context.Context) error {
	*m.events = append(*m.events, "stop:"+m.name)
	if m.onStop != nil {
		m.onStop(ctx)
	}
	return m.stopErr
}

func TestOrderedStartupAndConcurrentIdempotentShutdown(t *testing.T) {
	var events []string
	a := &testModule{name: "credentials", events: &events}
	b := &testModule{name: "workflow", events: &events}
	runtime, err := New(time.Second, a, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(runtime.Start(context.Background()), ErrState) {
		t.Fatal("duplicate start accepted")
	}
	b.onStop = func(ctx context.Context) {
		if b.workCtx.Err() != context.Canceled || ctx.Err() != nil {
			t.Error("work not canceled or shutdown context already canceled")
		}
	}
	var callers sync.WaitGroup
	for range 8 {
		callers.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := runtime.Stop(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	want := []string{"init:credentials", "init:workflow", "start:credentials", "start:workflow", "stop:workflow", "stop:credentials"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events %v, want %v", events, want)
	}
}

func TestFailedInitializationCleansPartialModuleWithoutStartingWork(t *testing.T) {
	var events []string
	failure := errors.New("init failed")
	a := &testModule{name: "a", events: &events}
	b := &testModule{name: "b", events: &events, initErr: failure}
	c := &testModule{name: "c", events: &events}
	runtime, err := New(time.Second, a, b, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("startup error lost: %v", err)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"init:a", "init:b", "stop:b", "stop:a"}) {
		t.Fatalf("unexpected lifecycle: %v", events)
	}
}

func TestStartFailureCleansAllInitializedModulesAndPreservesStopErrors(t *testing.T) {
	var events []string
	startFailure, stopFailure := errors.New("start failed"), errors.New("stop failed")
	a := &testModule{name: "a", events: &events}
	b := &testModule{name: "b", events: &events, startErr: startFailure, stopErr: stopFailure}
	c := &testModule{name: "c", events: &events}
	runtime, err := New(time.Second, a, b, c)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Start(context.Background())
	if !errors.Is(err, startFailure) || !errors.Is(err, stopFailure) {
		t.Fatalf("failure chain lost: %v", err)
	}
	if !reflect.DeepEqual(events, []string{"init:a", "init:b", "init:c", "start:a", "start:b", "stop:c", "stop:b", "stop:a"}) {
		t.Fatalf("unexpected lifecycle: %v", events)
	}
	if !errors.Is(runtime.Stop(context.Background()), stopFailure) {
		t.Fatal("shutdown error not retained")
	}
}

func TestCanceledStartupUsesFreshBoundedCleanupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []string
	a := &testModule{name: "a", events: &events, onInit: cancel}
	a.onStop = func(cleanupCtx context.Context) {
		if cleanupCtx.Err() != nil {
			t.Error("cleanup inherited startup cancellation")
		}
		if _, ok := cleanupCtx.Deadline(); !ok {
			t.Error("cleanup has no deadline")
		}
	}
	runtime, err := New(time.Second, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if !reflect.DeepEqual(events, []string{"init:a", "stop:a"}) {
		t.Fatalf("started work after cancellation: %v", events)
	}
}
