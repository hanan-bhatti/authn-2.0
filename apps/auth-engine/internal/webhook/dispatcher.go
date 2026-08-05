/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/dispatcher.go
 * Tier: Asynchronous Worker Engine
 *
 * Description: High-performance background worker pool for delivering signed HTTP
 *              webhooks to developer endpoints with zero API latency overhead.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/crypto"
)

type EventData struct {
	ID        string                 `json:"id"`
	EventType string                 `json:"event"`
	TenantID  string                 `json:"tenant_id"`
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

type DispatchTask struct {
	TenantID  string
	EventType string
	Data      map[string]interface{}
}

type Dispatcher struct {
	repo          *Repository
	encryptionKey string
	httpClient    *http.Client
	taskChan      chan DispatchTask
	workerCount   int
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewDispatcher(repo *Repository, encryptionKey string, workerCount int) *Dispatcher {
	if workerCount <= 0 {
		workerCount = 5
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Dispatcher{
		repo:          repo,
		encryptionKey: encryptionKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		taskChan:    make(chan DispatchTask, 1000), // 1000 buffered task queue
		workerCount: workerCount,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start launches background worker goroutines.
func (d *Dispatcher) Start() {
	for i := 0; i < d.workerCount; i++ {
		d.wg.Add(1)
		go d.workerLoop(i)
	}
	log.Printf("[Webhook Dispatcher] Started %d async worker goroutines", d.workerCount)
}

// Stop gracefully shuts down workers.
func (d *Dispatcher) Stop() {
	d.cancel()
	close(d.taskChan)
	d.wg.Wait()
	log.Println("[Webhook Dispatcher] Worker pool shut down cleanly")
}

// Dispatch queues an event for background worker delivery without blocking the calling thread.
func (d *Dispatcher) Dispatch(tenantID, eventType string, data map[string]interface{}) {
	select {
	case d.taskChan <- DispatchTask{TenantID: tenantID, EventType: eventType, Data: data}:
	default:
		log.Printf("[Webhook Dispatcher] Warning: task buffer full, dropping event '%s' for tenant '%s'", eventType, tenantID)
	}
}

func (d *Dispatcher) workerLoop(workerID int) {
	defer d.wg.Done()

	for task := range d.taskChan {
		d.processTask(task)
	}
}

func (d *Dispatcher) processTask(task DispatchTask) {
	ctx := context.Background()

	endpoints, err := d.repo.GetActiveEndpointsForEvent(ctx, task.TenantID, task.EventType)
	if err != nil || len(endpoints) == 0 {
		return
	}

	timestamp := time.Now().Unix()
	eventID := fmt.Sprintf("evt_%s", uuid.New().String()[:12])

	payloadObj := EventData{
		ID:        eventID,
		EventType: task.EventType,
		TenantID:  task.TenantID,
		Timestamp: timestamp,
		Data:      task.Data,
	}

	jsonBytes, err := json.Marshal(payloadObj)
	if err != nil {
		log.Printf("[Webhook Dispatcher] JSON marshal error: %v", err)
		return
	}

	for _, ep := range endpoints {
		d.deliverToEndpoint(ctx, ep, task.EventType, jsonBytes, payloadObj, timestamp)
	}
}

func (d *Dispatcher) deliverToEndpoint(ctx context.Context, ep *ent.WebhookEndpoint, eventType string, jsonBytes []byte, payloadObj EventData, timestamp int64) {
	// Decrypt endpoint secret key
	rawSecret, err := crypto.DecryptAES256GCM(ep.SecretKeyEncrypted, d.encryptionKey)
	if err != nil {
		log.Printf("[Webhook Dispatcher] Failed to decrypt secret for endpoint %s: %v", ep.ID, err)
		return
	}

	// Compute HMAC-SHA256 signature
	sig := SignPayload(rawSecret, timestamp, jsonBytes)
	sigHeader := FormatSignatureHeader(timestamp, sig)

	deliveryID := fmt.Sprintf("whd_%s", uuid.New().String()[:12])

	// Attempt delivery with 3 retries (1s, 3s, 5s backoff)
	var statusCode int
	var respBodyStr string
	var lastErr error
	var isSuccess bool

	backoffSchedule := []time.Duration{0, 1 * time.Second, 3 * time.Second}

	for attempt := 0; attempt < len(backoffSchedule); attempt++ {
		if attempt > 0 {
			time.Sleep(backoffSchedule[attempt])
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(jsonBytes))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Authn-Engine-Webhook/2.0")
		req.Header.Set("X-Authn-Signature", sigHeader)
		req.Header.Set("X-Authn-Event", eventType)
		req.Header.Set("X-Authn-Delivery", deliveryID)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		statusCode = resp.StatusCode
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) // Read max 4KB response snippet
		resp.Body.Close()
		respBodyStr = string(bodyBytes)

		if statusCode >= 200 && statusCode < 300 {
			isSuccess = true
			lastErr = nil
			break
		} else {
			lastErr = fmt.Errorf("server returned HTTP %d", statusCode)
		}
	}

	errMsg := ""
	if lastErr != nil {
		errMsg = lastErr.Error()
	}

	// Log delivery record in DB
	payloadMap := map[string]interface{}{
		"id":         payloadObj.ID,
		"event":      payloadObj.EventType,
		"tenant_id":  payloadObj.TenantID,
		"timestamp":  payloadObj.Timestamp,
		"data":       payloadObj.Data,
	}

	_, _ = d.repo.CreateDelivery(ctx, ep.ID, eventType, payloadMap, statusCode, respBodyStr, errMsg, isSuccess)
}

// DeliverSync sends a single synchronous ping payload to an endpoint (used for manual 'ping' testing).
func (d *Dispatcher) DeliverSync(ctx context.Context, ep *ent.WebhookEndpoint, eventType string, data map[string]interface{}) (*ent.WebhookEvent, error) {
	timestamp := time.Now().Unix()
	eventID := fmt.Sprintf("evt_%s", uuid.New().String()[:12])

	payloadObj := EventData{
		ID:        eventID,
		EventType: eventType,
		TenantID:  ep.TenantID,
		Timestamp: timestamp,
		Data:      data,
	}

	jsonBytes, err := json.Marshal(payloadObj)
	if err != nil {
		return nil, fmt.Errorf("marshal payload error: %w", err)
	}

	rawSecret, err := crypto.DecryptAES256GCM(ep.SecretKeyEncrypted, d.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret error: %w", err)
	}

	sig := SignPayload(rawSecret, timestamp, jsonBytes)
	sigHeader := FormatSignatureHeader(timestamp, sig)
	deliveryID := fmt.Sprintf("whd_%s", uuid.New().String()[:12])

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("build HTTP request error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Authn-Engine-Webhook/2.0")
	req.Header.Set("X-Authn-Signature", sigHeader)
	req.Header.Set("X-Authn-Event", eventType)
	req.Header.Set("X-Authn-Delivery", deliveryID)

	resp, err := d.httpClient.Do(req)

	var statusCode int
	var respBodyStr string
	var errMsg string
	isSuccess := false

	if err != nil {
		errMsg = err.Error()
	} else {
		statusCode = resp.StatusCode
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		respBodyStr = string(bodyBytes)
		if statusCode >= 200 && statusCode < 300 {
			isSuccess = true
		} else {
			errMsg = fmt.Sprintf("HTTP %d", statusCode)
		}
	}

	payloadMap := map[string]interface{}{
		"id":        payloadObj.ID,
		"event":     payloadObj.EventType,
		"tenant_id": payloadObj.TenantID,
		"timestamp": payloadObj.Timestamp,
		"data":      payloadObj.Data,
	}

	return d.repo.CreateDelivery(ctx, ep.ID, eventType, payloadMap, statusCode, respBodyStr, errMsg, isSuccess)
}
