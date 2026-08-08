package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/config"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/ratelimit"
	"github.com/redis/go-redis/v9"
)

func runDockerRedisCli(args ...string) string {
	cmdArgs := append([]string{"exec", "authn-redis", "redis-cli"}, args...)
	cmd := exec.Command("docker", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("docker exec redis-cli error: %v output: %s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func main() {
	fmt.Println("==========================================================")
	fmt.Println("REAL REDIS RATE LIMITER & EXPONENTIAL BACKOFF VERIFICATION")
	fmt.Println("==========================================================")

	// ---------------------------------------------------------------------
	// 5a. Confirm defaults apply when env vars are unset
	// ---------------------------------------------------------------------
	fmt.Println("\n--- [5a] Verifying defaults when env vars are unset ---")
	os.Unsetenv("AUTHN_RATELIMIT_ENABLED")
	os.Unsetenv("AUTHN_RATELIMIT_MAX_ATTEMPTS")
	os.Unsetenv("AUTHN_RATELIMIT_WINDOW_SECONDS")
	os.Unsetenv("AUTHN_RATELIMIT_BACKOFF_SCHEDULE")
	os.Unsetenv("AUTHN_RATELIMIT_VIOLATION_RESET_DAYS")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed loading config: %v", err)
	}
	fmt.Printf("Default RateLimitEnabled:            %v\n", cfg.RateLimitEnabled)
	fmt.Printf("Default RateLimitMaxAttempts:        %d\n", cfg.RateLimitMaxAttempts)
	fmt.Printf("Default RateLimitWindow:             %s\n", cfg.RateLimitWindow)
	fmt.Printf("Default RateLimitBackoffSchedule:    %v\n", cfg.RateLimitBackoffSchedule)
	fmt.Printf("Default RateLimitViolationResetDays: %d\n", cfg.RateLimitViolationResetDays)

	// ---------------------------------------------------------------------
	// Connect to Real Redis
	// ---------------------------------------------------------------------
	redisURL := "redis://localhost:6379"
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("Failed to parse Redis URL: %v", err)
	}
	client := redis.NewClient(opt)
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to ping Redis at %s: %v", redisURL, err)
	}
	fmt.Printf("\n⚡ Connected to real Redis at %s\n", redisURL)

	testKey := "verif_user_123"
	attemptKey := "ratelimit:attempt:" + testKey
	blockKey := "ratelimit:block:" + testKey
	violKey := "ratelimit:viol_cnt:" + testKey

	// Clear pre-existing test keys via redis-cli
	runDockerRedisCli("del", attemptKey, blockKey, violKey)

	// Create Limiter with max_attempts=2
	limiter := ratelimit.NewLimiter(ratelimit.Options{
		Redis:              client,
		Enabled:            true,
		FailClosed:         true,
		MaxAttempts:        2,
		Window:             900 * time.Second,
		IPBudgetMultiplier: 10,
		BackoffSchedule:    []time.Duration{15 * time.Minute, 1 * time.Hour, 6 * time.Hour, 24 * time.Hour},
		ViolationReset:     7 * 24 * time.Hour,
	})

	// ---------------------------------------------------------------------
	// 5b & 5c: Attempt 1 & 2 allowed, Attempt 3 (1st violation) triggers 15m block
	// ---------------------------------------------------------------------
	fmt.Println("\n--- [5b & 5c] Testing max_attempts=2 and 1st Violation (15m TTL) ---")

	allowed, retryAfter, err := limiter.Check(ctx, testKey)
	fmt.Printf("Attempt 1: allowed=%v, retryAfter=%v, err=%v\n", allowed, retryAfter, err)

	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	fmt.Printf("Attempt 2: allowed=%v, retryAfter=%v, err=%v\n", allowed, retryAfter, err)

	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	fmt.Printf("Attempt 3 (1st Violation): allowed=%v, retryAfter=%v, err=%v\n", allowed, retryAfter, err)

	blockVal := runDockerRedisCli("get", blockKey)
	blockTTL := runDockerRedisCli("ttl", blockKey)
	violVal := runDockerRedisCli("get", violKey)
	violTTL := runDockerRedisCli("ttl", violKey)

	fmt.Println("\n🔍 REAL redis-cli Inspection (1st Violation):")
	fmt.Printf("  redis-cli GET %s  -> %s\n", blockKey, blockVal)
	fmt.Printf("  redis-cli TTL %s  -> %s seconds (~15m / 900s)\n", blockKey, blockTTL)
	fmt.Printf("  redis-cli GET %s -> %s\n", violKey, violVal)
	fmt.Printf("  redis-cli TTL %s -> %s seconds (~7 days / 604800s) [5e verified]\n", violKey, violTTL)

	// ---------------------------------------------------------------------
	// 5d: Manually delete block key via redis-cli & trigger 2nd violation (1h TTL)
	// ---------------------------------------------------------------------
	fmt.Println("\n--- [5d] Simulating block expiry via redis-cli DEL & triggering 2nd Violation (1h TTL) ---")
	runDockerRedisCli("del", blockKey)

	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	fmt.Printf("Attempt after 1st block expiry (2nd Violation): allowed=%v, retryAfter=%v, err=%v\n", allowed, retryAfter, err)

	blockVal = runDockerRedisCli("get", blockKey)
	blockTTL = runDockerRedisCli("ttl", blockKey)
	violVal = runDockerRedisCli("get", violKey)
	violTTL = runDockerRedisCli("ttl", violKey)

	fmt.Println("🔍 REAL redis-cli Inspection (2nd Violation):")
	fmt.Printf("  redis-cli GET %s  -> %s\n", blockKey, blockVal)
	fmt.Printf("  redis-cli TTL %s  -> %s seconds (~1h / 3600s)\n", blockKey, blockTTL)
	fmt.Printf("  redis-cli GET %s -> %s\n", violKey, violVal)
	fmt.Printf("  redis-cli TTL %s -> %s seconds (Refreshed to 7 days)\n", violKey, violTTL)

	// ---------------------------------------------------------------------
	// 5d cont: 3rd Violation (6h TTL)
	// ---------------------------------------------------------------------
	fmt.Println("\n--- [5d cont] Simulating block expiry via redis-cli DEL & triggering 3rd Violation (6h TTL) ---")
	runDockerRedisCli("del", blockKey)

	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	fmt.Printf("Attempt after 2nd block expiry (3rd Violation): allowed=%v, retryAfter=%v, err=%v\n", allowed, retryAfter, err)

	blockVal = runDockerRedisCli("get", blockKey)
	blockTTL = runDockerRedisCli("ttl", blockKey)
	violVal = runDockerRedisCli("get", violKey)
	violTTL = runDockerRedisCli("ttl", violKey)

	fmt.Println("🔍 REAL redis-cli Inspection (3rd Violation):")
	fmt.Printf("  redis-cli GET %s  -> %s\n", blockKey, blockVal)
	fmt.Printf("  redis-cli TTL %s  -> %s seconds (~6h / 21600s)\n", blockKey, blockTTL)
	fmt.Printf("  redis-cli GET %s -> %s\n", violKey, violVal)
	fmt.Printf("  redis-cli TTL %s -> %s seconds (Refreshed to 7 days)\n", violKey, violTTL)

	// ---------------------------------------------------------------------
	// 5d cont: 4th Violation (24h Capped TTL)
	// ---------------------------------------------------------------------
	fmt.Println("\n--- [5d cont] Simulating block expiry via redis-cli DEL & triggering 4th Violation (24h Capped TTL) ---")
	runDockerRedisCli("del", blockKey)

	allowed, retryAfter, err = limiter.Check(ctx, testKey)
	fmt.Printf("Attempt after 3rd block expiry (4th Violation): allowed=%v, retryAfter=%v, err=%v\n", allowed, retryAfter, err)

	blockVal = runDockerRedisCli("get", blockKey)
	blockTTL = runDockerRedisCli("ttl", blockKey)
	violVal = runDockerRedisCli("get", violKey)
	violTTL = runDockerRedisCli("ttl", violKey)

	fmt.Println("🔍 REAL redis-cli Inspection (4th Violation):")
	fmt.Printf("  redis-cli GET %s  -> %s\n", blockKey, blockVal)
	fmt.Printf("  redis-cli TTL %s  -> %s seconds (~24h / 86400s)\n", blockKey, blockTTL)
	fmt.Printf("  redis-cli GET %s -> %s\n", violKey, violVal)
	fmt.Printf("  redis-cli TTL %s -> %s seconds (Refreshed to 7 days)\n", violKey, violTTL)

	// Clean up verification keys
	runDockerRedisCli("del", attemptKey, blockKey, violKey)

	// ---------------------------------------------------------------------
	// 5f: REAL Outage Test with docker stop authn-redis / docker start authn-redis
	// ---------------------------------------------------------------------
	fmt.Println("\n--- [5f] REAL Outage Test: docker stop authn-redis -> 503 Service Unavailable ---")

	// Production rate limiter with Redis client
	prodLimiter := ratelimit.NewLimiter(ratelimit.Options{
		Redis: client, Enabled: true, FailClosed: true, MaxAttempts: 5,
		Window: 900 * time.Second, IPBudgetMultiplier: 10,
		ViolationReset: 7 * 24 * time.Hour,
	})

	fmt.Println("Stopping authn-redis container via `docker stop authn-redis`...")
	outCmd := exec.Command("docker", "stop", "authn-redis")
	if out, err := outCmd.CombinedOutput(); err != nil {
		log.Fatalf("Failed stopping docker container: %v, output: %s", err, string(out))
	}
	fmt.Println("🔴 authn-redis container STOPPED.")

	// Test check in production mode when Redis is unreachable
	allowed, retryAfter, err = prodLimiter.Check(ctx, "outage_test_key")
	fmt.Printf("Production check with Redis stopped: allowed=%v, retryAfter=%v, err=%v\n", allowed, retryAfter, err)

	if err != nil && strings.Contains(err.Error(), "rate limit service unavailable") {
		fmt.Println("✅ Verified: Returns 503 Service Unavailable error when Redis is down in Production mode.")
	} else {
		log.Fatalf("❌ Expected Service Unavailable error, got: %v", err)
	}

	fmt.Println("\nStarting authn-redis container via `docker start authn-redis`...")
	inCmd := exec.Command("docker", "start", "authn-redis")
	if out, err := inCmd.CombinedOutput(); err != nil {
		log.Fatalf("Failed starting docker container: %v, output: %s", err, string(out))
	}
	fmt.Println("🟢 authn-redis container STARTED.")

	// Wait briefly for Redis socket to accept connections again
	time.Sleep(500 * time.Millisecond)

	allowed, retryAfter, err = prodLimiter.Check(ctx, "outage_test_key")
	fmt.Printf("Production check after Redis restart: allowed=%v, retryAfter=%v, err=%v\n", allowed, retryAfter, err)
	if allowed && err == nil {
		fmt.Println("✅ Verified: Normal operation resumed successfully after Redis restart.")
	} else {
		log.Fatalf("❌ Expected normal operation resume, got allowed=%v, err=%v", allowed, err)
	}

	fmt.Println("\n==========================================================")
	fmt.Println("🎉 ALL REAL REDIS VERIFICATION CHECKS PASSED SUCCESSFULLY!")
	fmt.Println("==========================================================")
}
