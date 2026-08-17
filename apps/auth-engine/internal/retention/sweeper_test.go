/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/retention/sweeper_test.go
 * Tier: Infrastructure / Data Retention / Tests
 *
 * Description: Covers the scheduler's contract with its tasks: every task runs,
 *              one failing task does not shield the rest, the context a task
 *              receives can actually cross tenant boundaries and carries a
 *              deadline, and both a misconfigured interval and a shutdown
 *              mid-sweep leave the process in a defined state.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package retention

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
)

// recorder collects the task names that ran, in order, under a mutex because a
// sweep started by the loop runs on its own goroutine.
type recorder struct {
	mu    sync.Mutex
	names []string
}

func (r *recorder) task(name string, removed int, err error) Task {
	return Task{
		Name: name,
		Run: func(context.Context) (int, error) {
			r.mu.Lock()
			r.names = append(r.names, name)
			r.mu.Unlock()
			return removed, err
		},
	}
}

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.names...)
}

// TestSweepOnceRunsEveryTaskInOrder pins the sequence, because the tasks are
// registered cheapest-first so that a sweep cut short by its deadline has
// already dealt with the tables that grow fastest.
func TestSweepOnceRunsEveryTaskInOrder(t *testing.T) {
	rec := &recorder{}
	s := New(time.Minute, nil,
		rec.task("first", 1, nil),
		rec.task("second", 2, nil),
		rec.task("third", 0, nil),
	)

	s.SweepOnce(context.Background())

	got := rec.seen()
	want := []string{"first", "second", "third"}
	if len(got) != len(want) {
		t.Fatalf("ran %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ran %v, want %v", got, want)
		}
	}
}

// TestSweepOnceContinuesAfterAFailingTask is the property that keeps one table's
// problem from becoming every table's problem: a constraint violation or a lock
// timeout on sessions must not stop social auth state from being swept for the
// rest of the deployment's life.
func TestSweepOnceContinuesAfterAFailingTask(t *testing.T) {
	rec := &recorder{}
	s := New(time.Minute, nil,
		rec.task("healthy-before", 3, nil),
		rec.task("broken", 0, errors.New("deadlock detected")),
		rec.task("healthy-after", 4, nil),
	)

	s.SweepOnce(context.Background())

	if len(rec.seen()) != 3 {
		t.Fatalf("ran %v, want all three tasks despite the middle one failing", rec.seen())
	}
}

// TestSweepOnceGrantsTasksACrossTenantContext guards the arrangement the purge
// queries depend on. They select without a tenant filter, which the privacy
// interceptors refuse unless the context carries a bypass, so a sweep handed an
// ordinary context would fail every task with an authorization error rather than
// deleting anything.
func TestSweepOnceGrantsTasksACrossTenantContext(t *testing.T) {
	var seen *privacy.PrivacyContext
	var deadlineSet bool

	s := New(time.Minute, nil, Task{
		Name: "inspect",
		Run: func(ctx context.Context) (int, error) {
			seen, _ = privacy.FromContext(ctx)
			_, deadlineSet = ctx.Deadline()
			return 0, nil
		},
	})

	s.SweepOnce(context.Background())

	if seen == nil {
		t.Fatal("task received a context with no privacy scope at all")
	}
	if !seen.Bypass {
		t.Error("task received a scoped context; cross-tenant sweeps require Bypass")
	}
	if !deadlineSet {
		t.Error("task received a context with no deadline; a stalled sweep would run until shutdown")
	}
}

// TestNewClampsAnUnusableInterval covers the two ways an operator can express
// "never sweep" in configuration. Zero panics time.NewTicker, and a negative
// value would tick continuously, so neither can be honoured — and silently not
// sweeping is the failure this package exists to prevent.
func TestNewClampsAnUnusableInterval(t *testing.T) {
	for _, given := range []time.Duration{0, -time.Hour} {
		s := New(given, nil, Task{Name: "noop", Run: func(context.Context) (int, error) { return 0, nil }})
		if s.interval != defaultInterval {
			t.Errorf("New(%s).interval = %s, want the %s fallback", given, s.interval, defaultInterval)
		}
	}
}

// TestStartWithoutTasksIsStoppable pins that a sweeper with nothing registered
// still closes its done channel, so a Stop in the shutdown path returns instead
// of blocking the process from exiting.
func TestStartWithoutTasksIsStoppable(t *testing.T) {
	s := New(time.Minute, nil)
	s.Start()

	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked on a sweeper that was started with no tasks")
	}
}

// TestStopCancelsTheTaskContext is the shutdown contract. Tasks delete in
// batches and are resumable, so a sweep in flight when the server drains should
// give up at its next batch boundary rather than hold the process open for the
// remainder of its deadline.
func TestStopCancelsTheTaskContext(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})

	s := New(50*time.Millisecond, nil, Task{
		Name: "long-running",
		Run: func(ctx context.Context) (int, error) {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			return 0, ctx.Err()
		},
	})

	s.Start()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first sweep never started")
	}

	s.Stop()

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop returned without cancelling the in-flight task's context")
	}
}

// TestAcquireLeaseAdmitsTheSweepWithoutRedis covers the single-server
// deployment. Refusing to sweep without a lease server would mean a deployment
// running REDIS_REQUIRED=false never retains anything.
func TestAcquireLeaseAdmitsTheSweepWithoutRedis(t *testing.T) {
	s := New(time.Minute, nil)
	if !s.acquireLease(context.Background()) {
		t.Error("acquireLease = false with no Redis configured; the sweep would never run")
	}
}
