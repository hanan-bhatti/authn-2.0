/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/retention/sweeper.go
 * Tier: Infrastructure / Data Retention
 *
 * Description: Background scheduler that runs each table's retention rule on an
 *              interval. The rules themselves live with the schemas they delete
 *              from; this package decides when they run, which server runs them,
 *              and how long they are allowed to take.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package retention

import (
	"context"
	"log"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/privacy"
	"github.com/redis/go-redis/v9"
)

const (
	// leaseKey is the fleet-wide lock a server holds while it sweeps.
	leaseKey = "retention:sweep:lease"

	// defaultInterval is used when the caller supplies a non-positive one. A zero
	// interval would panic time.NewTicker, and silently never sweeping is the
	// failure this package exists to prevent, so it is not an option either.
	defaultInterval = 15 * time.Minute
)

// Task is one table's retention rule: a name for the log line, and a function
// that deletes what has aged out and reports how many rows it removed.
//
// Run receives a context that already carries a privacy bypass, because sweeps
// span every tenant, and a deadline of one sweep interval. A task is expected to
// delete in bounded batches, so that hitting the deadline leaves a partly swept
// table rather than an aborted transaction — the next sweep resumes from there.
type Task struct {
	Name string
	Run  func(ctx context.Context) (int, error)
}

// Sweeper runs its tasks on an interval for the lifetime of the process.
//
// One instance per server. Where several servers share a database they all tick,
// so the sweeper takes a Redis lease to keep a single one of them doing the work.
// Absent Redis every server sweeps: duplicated queries cost something, but they
// cannot corrupt anything, because each task deletes by primary key in ascending
// order — two servers therefore take row locks in the same sequence instead of
// deadlocking, and a row deleted twice is simply absent the second time.
type Sweeper struct {
	tasks    []Task
	interval time.Duration
	redis    *redis.Client
	stop     chan struct{}
	done     chan struct{}
}

// New returns a sweeper over tasks. A nil Redis client disables the lease.
func New(interval time.Duration, redisClient *redis.Client, tasks ...Task) *Sweeper {
	if interval <= 0 {
		log.Printf("retention: interval %s is not usable, falling back to %s", interval, defaultInterval)
		interval = defaultInterval
	}

	return &Sweeper{
		tasks:    tasks,
		interval: interval,
		redis:    redisClient,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start begins sweeping in the background. It must be called at most once.
//
// The first sweep runs one interval in rather than at startup. A deployment
// adopting retention has a backlog to clear, and boot is the worst moment to
// clear it: connection pools are still filling and sign-in traffic has the least
// headroom to share the database.
func (s *Sweeper) Start() {
	if len(s.tasks) == 0 {
		log.Print("retention: no tasks registered, sweeper not started")
		close(s.done)
		return
	}

	log.Printf("retention: sweeping %d tables every %s", len(s.tasks), s.interval)
	go s.loop()
}

// Stop ends the sweep loop and waits for an in-flight sweep to unwind. It must
// be called at most once, and only after Start.
func (s *Sweeper) Stop() {
	close(s.stop)
	<-s.done
}

func (s *Sweeper) loop() {
	defer close(s.done)

	// Cancelled by Stop so that a sweep running during shutdown gives up at its
	// next batch boundary instead of holding the process open for its full
	// deadline. Every task is resumable, so abandoning one loses no progress.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-s.stop
		cancel()
	}()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.acquireLease(ctx) {
				s.SweepOnce(ctx)
			}
		}
	}
}

// SweepOnce runs every task once, in order, and logs what each removed.
//
// A task that fails does not stop the ones after it: one table's constraint
// problem must not stall every other table's growth. Tasks that removed nothing
// log nothing, so a healthy deployment stays quiet rather than emitting a line
// per table per interval.
//
// Exported without the lease check so a deployment can drive a sweep from a job
// runner or a one-off command instead of the in-process ticker.
func (s *Sweeper) SweepOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(privacy.NewBypassContext(ctx), s.interval)
	defer cancel()

	for _, task := range s.tasks {
		removed, err := task.Run(ctx)
		switch {
		case err != nil:
			log.Printf("retention: %s sweep failed after removing %d rows: %v", task.Name, removed, err)
		case removed > 0:
			log.Printf("retention: %s sweep removed %d rows", task.Name, removed)
		}
	}
}

// acquireLease reports whether this server should perform the next sweep.
//
// The lease is never released explicitly — it expires — so that one sweep runs
// per interval across the fleet rather than one per server per interval. It is
// held for slightly less than an interval so the next tick does not arrive while
// the previous holder's key is still alive and skip a round.
//
// Any Redis problem, including Redis not being configured at all, admits the
// sweep. Duplicated work is a far cheaper failure than a deployment that never
// sweeps, which is what refusing here would produce for every single-server
// installation running without Redis.
func (s *Sweeper) acquireLease(ctx context.Context) bool {
	if s.redis == nil {
		return true
	}

	ttl := s.interval - s.interval/10
	acquired, err := s.redis.SetNX(ctx, leaseKey, time.Now().UTC().Format(time.RFC3339), ttl).Result()
	if err != nil {
		return true
	}

	return acquired
}
