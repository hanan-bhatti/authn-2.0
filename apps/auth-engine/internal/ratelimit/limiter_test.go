package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestLimiter_InMemorySlidingWindow(t *testing.T) {
	schedule := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	limiter := NewLimiter(nil, false, true, true, 5, 60, schedule, 7)
	ctx := context.Background()
	key := "test_ratelimit_key"

	// 5 attempts allowed
	for i := 1; i <= 5; i++ {
		allowed, _, err := limiter.Check(ctx, key)
		if err != nil {
			t.Fatalf("unexpected error on attempt %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("expected attempt %d to be allowed", i)
		}
	}

	// 6th attempt blocked (429)
	allowed, _, err := limiter.Check(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error on 6th attempt: %v", err)
	}
	if allowed {
		t.Fatalf("expected 6th attempt to be blocked")
	}
}

func TestLimiter_FailClosedProduction(t *testing.T) {
	schedule := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	// Production mode without Redis connection must fail-closed
	limiter := NewLimiter(nil, true, true, true, 5, 60, schedule, 7)
	ctx := context.Background()

	allowed, _, err := limiter.Check(ctx, "test_prod_key")
	if allowed {
		t.Fatalf("expected fail-closed production check to deny access when Redis is nil")
	}
	if err == nil {
		t.Fatalf("expected ErrRedisUnavailable error in production fail-closed mode")
	}
}

func TestLimiter_RedisExponentialBackoff(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("skipping Redis integration test: Redis not reachable on localhost:6379")
	}

	schedule := []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour}
	limiter := NewLimiter(client, false, true, true, 2, 60, schedule, 7)

	testKey := "test_backoff_key_unit"
	attemptKey := "ratelimit:attempt:" + testKey
	blockKey := "ratelimit:block:" + testKey
	violKey := "ratelimit:viol_cnt:" + testKey

	// Cleanup key before test
	client.Del(ctx, attemptKey, blockKey, violKey)
	t.Cleanup(func() {
		client.Del(ctx, attemptKey, blockKey, violKey)
	})

	// 2 attempts allowed
	for i := 1; i <= 2; i++ {
		allowed, _, err := limiter.Check(ctx, testKey)
		if err != nil || !allowed {
			t.Fatalf("attempt %d should be allowed, got allowed=%v, err=%v", i, allowed, err)
		}
	}

	// Violation 1 (3rd attempt): should trigger 15m block
	allowed, retryAfter, err := limiter.Check(ctx, testKey)
	if allowed || err != nil {
		t.Fatalf("3rd attempt should be blocked, got allowed=%v, err=%v", allowed, err)
	}
	if retryAfter != 15*time.Minute {
		t.Fatalf("expected 1st violation retryAfter to be 15m, got %v", retryAfter)
	}

	// Verify Redis block key TTL is ~15m (900s)
	ttl, _ := client.TTL(ctx, blockKey).Result()
	if ttl < 890*time.Second || ttl > 900*time.Second {
		t.Fatalf("expected block TTL ~900s, got %v", ttl)
	}

	// Verify violation counter key TTL is ~7 days (604800s)
	violTTL, _ := client.TTL(ctx, violKey).Result()
	if violTTL < 604700*time.Second || violTTL > 604800*time.Second {
		t.Fatalf("expected violation count TTL ~604800s, got %v", violTTL)
	}

	// Simulate block expiry via DEL
	client.Del(ctx, blockKey)

	// Violation 2: should trigger 1h block
	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	if allowed || retryAfter != 1*time.Hour {
		t.Fatalf("expected 2nd violation 1h block, got allowed=%v, retryAfter=%v", allowed, retryAfter)
	}

	// Simulate block expiry via DEL
	client.Del(ctx, blockKey)

	// Violation 3: should trigger 6h block
	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	if allowed || retryAfter != 6*time.Hour {
		t.Fatalf("expected 3rd violation 6h block, got allowed=%v, retryAfter=%v", allowed, retryAfter)
	}

	// Simulate block expiry via DEL
	client.Del(ctx, blockKey)

	// Violation 4: should trigger 24h block (capped)
	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	if allowed || retryAfter != 24*time.Hour {
		t.Fatalf("expected 4th violation 24h block cap, got allowed=%v, retryAfter=%v", allowed, retryAfter)
	}
}

func TestBuildKey(t *testing.T) {
	key1 := BuildKey("tnt_demo", "127.0.0.1", "Mozilla/5.0", "/v1/client/login")
	key2 := BuildKey("tnt_demo", "127.0.0.1", "Mozilla/5.0", "/v1/client/login")
	key3 := BuildKey("tnt_demo", "192.168.1.1", "Mozilla/5.0", "/v1/client/login")

	if key1 != key2 {
		t.Fatalf("expected identical keys for identical inputs")
	}
	if key1 == key3 {
		t.Fatalf("expected different keys for different IP addresses")
	}
}
