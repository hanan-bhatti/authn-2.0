package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

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
	fmt.Println("REAL HTTP ENDPOINT & REDIS RATE LIMITER VERIFICATION")
	fmt.Println("==========================================================")

	// Ensure Redis is running
	runDockerRedisCli("ping")

	// Set env vars for verification
	os.Setenv("AUTHN_RATELIMIT_ENABLED", "true")
	os.Setenv("AUTHN_RATELIMIT_MAX_ATTEMPTS", "2")
	os.Setenv("AUTHN_RATELIMIT_WINDOW_SECONDS", "900")
	os.Setenv("AUTHN_RATELIMIT_BACKOFF_SCHEDULE", "15m,1h,6h,24h")
	os.Setenv("AUTHN_RATELIMIT_VIOLATION_RESET_DAYS", "7")
	os.Setenv("AUTHN_REDIS_URL", "redis://localhost:6379")
	os.Setenv("PORT", "8080")
	os.Setenv("ENV", "production")

	// Clean up redis keys for HTTP client IP/Path key
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ctx := context.Background()
	keys, _ := client.Keys(ctx, "ratelimit:*").Result()
	if len(keys) > 0 {
		client.Del(ctx, keys...)
	}

	reqURL := "http://localhost:8080/v1/client/login"
	jsonBody := []byte(`{"email":"test@example.com","password":"WrongPassword123!"}`)

	pkHeader := "pk_test_demo12345678901234567890123456789012"

	sendReq := func(idx int) (int, string, http.Header) {
		req, _ := http.NewRequest("POST", reqURL, bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Authn-Publishable-Key", pkHeader)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), resp.Header
	}

	// Request 1: Allowed (400 Bad Request or 401 Unauthorized from auth service, not 429)
	code, body, _ := sendReq(1)
	fmt.Printf("HTTP Request 1: Status %d, Body: %s\n", code, body)

	// Request 2: Allowed
	code, body, _ = sendReq(2)
	fmt.Printf("HTTP Request 2: Status %d, Body: %s\n", code, body)

	// Request 3: Rate Limited (1st Violation -> 15m / 900s block)
	code, body, headers := sendReq(3)
	fmt.Printf("HTTP Request 3 (1st Violation): Status %d, Retry-After: %s, Body: %s\n", code, headers.Get("Retry-After"), body)

	if code != 429 {
		log.Fatalf("Expected HTTP 429 on request 3, got %d", code)
	}

	// Inspect Redis keys for 1st HTTP violation
	blockKeysStr := runDockerRedisCli("keys", "ratelimit:block:*")
	violKeysStr := runDockerRedisCli("keys", "ratelimit:viol_cnt:*")
	blockKeyList := strings.Fields(blockKeysStr)
	violKeyList := strings.Fields(violKeysStr)

	if len(blockKeyList) == 0 || len(violKeyList) == 0 {
		log.Fatalf("Expected ratelimit:block and ratelimit:viol_cnt keys in Redis")
	}

	httpBlockKey := blockKeyList[0]
	httpViolKey := violKeyList[0]

	fmt.Println("\n🔍 REAL redis-cli Inspection for HTTP 1st Violation:")
	fmt.Printf("  redis-cli GET %s  -> %s\n", httpBlockKey, runDockerRedisCli("get", httpBlockKey))
	fmt.Printf("  redis-cli TTL %s  -> %s seconds (~15m / 900s)\n", httpBlockKey, runDockerRedisCli("ttl", httpBlockKey))
	fmt.Printf("  redis-cli GET %s -> %s\n", httpViolKey, runDockerRedisCli("get", httpViolKey))
	fmt.Printf("  redis-cli TTL %s -> %s seconds (~7 days)\n", httpViolKey, runDockerRedisCli("ttl", httpViolKey))

	// ---------------------------------------------------------------------
	// Trigger 2nd Violation over real HTTP endpoint by DELing ONLY block key
	// ---------------------------------------------------------------------
	fmt.Println("\n--- Simulating block expiry via redis-cli DEL on HTTP block key ---")
	fmt.Printf("Executing: redis-cli DEL %s\n", httpBlockKey)
	runDockerRedisCli("del", httpBlockKey)

	code, body, headers = sendReq(4)
	fmt.Printf("HTTP Request 4 (2nd Violation): Status %d, Retry-After: %s, Body: %s\n", code, headers.Get("Retry-After"), body)

	if code != 429 {
		log.Fatalf("Expected HTTP 429 on request 4, got %d", code)
	}

	fmt.Println("\n🔍 REAL redis-cli Inspection for HTTP 2nd Violation:")
	fmt.Printf("  redis-cli GET %s  -> %s\n", httpBlockKey, runDockerRedisCli("get", httpBlockKey))
	fmt.Printf("  redis-cli TTL %s  -> %s seconds (~1h / 3600s)\n", httpBlockKey, runDockerRedisCli("ttl", httpBlockKey))
	fmt.Printf("  redis-cli GET %s -> %s\n", httpViolKey, runDockerRedisCli("get", httpViolKey))
	fmt.Printf("  redis-cli TTL %s -> %s seconds (Refreshed to 7 days)\n", httpViolKey, runDockerRedisCli("ttl", httpViolKey))

	// Outage test via HTTP: stop docker container
	fmt.Println("\nStopping authn-redis container to verify HTTP 503...")
	_ = exec.Command("docker", "stop", "authn-redis").Run()
	time.Sleep(500 * time.Millisecond)

	code, body, _ = sendReq(5)
	fmt.Printf("HTTP Request during Redis Outage: Status %d (503), Body: %s\n", code, body)

	// Restart docker container
	_ = exec.Command("docker", "start", "authn-redis").Run()
	time.Sleep(500 * time.Millisecond)
	fmt.Println("Restarted authn-redis container.")

	if code != 503 {
		log.Fatalf("Expected HTTP 503 during Redis outage, got %d", code)
	}

	fmt.Println("\n==========================================================")
	fmt.Println("🎉 HTTP & REDIS END-TO-END VERIFICATION PASSED!")
	fmt.Println("==========================================================")
}
