/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/webhook/dispatcher.go
 * Tier: Asynchronous Worker Engine
 *
 * Delivers signed webhook payloads to subscriber endpoints from a background
 * worker pool.
 *
 * Delivery is asynchronous because the destination is a third party's server.
 * Sending inline would put an unrelated operator's outage on the critical path
 * of a login, so the request path only enqueues; workers own the network call,
 * the retries and the logging.
 *
 * The queue is bounded and lossy under pressure. When it fills, events are
 * dropped with a warning rather than blocking the caller: a webhook is a
 * notification, and delaying authentication to guarantee its delivery is the
 * wrong trade. Delivery is at-most-once and endpoints must treat it that way.
 *
 * Every delivery is recorded, successful or not, so an operator can see what
 * was attempted and replay it.
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

const (
	// defaultWorkerCount is the pool size used when the caller requests none.
	// Workers spend nearly all their time waiting on the network, so the count
	// governs delivery concurrency rather than CPU use.
	defaultWorkerCount = 5

	// taskQueueSize is the number of events buffered ahead of the workers. It
	// absorbs a burst — a bulk import firing thousands of user.created events —
	// without blocking the request path, and bounds how much memory a
	// misbehaving endpoint can cause to accumulate.
	taskQueueSize = 1000

	// deliveryTimeout caps one delivery attempt. It is deliberately short:
	// subscriber endpoints are third-party servers of unknown quality, and a
	// slow one must not occupy a worker that other tenants' events are queued
	// behind.
	deliveryTimeout = 5 * time.Second

	// responseSnippetBytes is how much of an endpoint's response is retained
	// for the delivery log. Enough to show an error message, bounded so that an
	// endpoint returning a large body cannot inflate the log table.
	responseSnippetBytes = 4096

	// userAgent identifies these requests to subscribers, so an endpoint can
	// recognise and filter them.
	userAgent = "Authn-Engine-Webhook/2.0"
)

// retryBackoff is the wait before each delivery attempt, so its length is the
// number of attempts made.
//
// The first entry is zero because the first attempt is immediate; the later
// waits give a briefly overloaded endpoint room to recover. Retries are
// deliberately few and short — a worker waiting is a worker not delivering
// other events, and a genuinely down endpoint is better served by the operator
// replaying from the delivery log.
var retryBackoff = []time.Duration{0, 1 * time.Second, 3 * time.Second}

// EventData is the payload delivered to subscribers. Its JSON shape is a public
// contract: subscribers parse these fields, so renaming one breaks them.
type EventData struct {
	// ID uniquely identifies this event, letting a subscriber discard a
	// duplicate if one is ever replayed.
	ID string `json:"id"`
	// EventType is the event name, matching the subscription list.
	EventType string `json:"event"`
	// TenantID is the tenant the event belongs to.
	TenantID string `json:"tenant_id"`
	// Timestamp is the emission time in Unix seconds. It is also the value
	// covered by the signature.
	Timestamp int64 `json:"timestamp"`
	// Data is the event-specific body.
	Data map[string]interface{} `json:"data"`
}

// DispatchTask is one queued unit of work: an event to fan out to whichever
// endpoints subscribe to it.
type DispatchTask struct {
	// TenantID scopes the endpoint lookup.
	TenantID string
	// EventType selects the subscribing endpoints.
	EventType string
	// Data is the event-specific body.
	Data map[string]interface{}
}

// Dispatcher owns the worker pool and the queue feeding it.
type Dispatcher struct {
	// repo resolves subscribing endpoints and records delivery attempts.
	repo *Repository
	// encryptionKey decrypts each endpoint's stored signing secret.
	encryptionKey string
	// httpClient is shared by all workers so connections to a frequently
	// notified endpoint are pooled rather than reopened per delivery.
	httpClient *http.Client
	// taskChan is the bounded queue between the request path and the workers.
	taskChan chan DispatchTask
	// workerCount is the number of goroutines Start launches.
	workerCount int
	// wg tracks the workers so Stop can wait for the queue to drain.
	wg sync.WaitGroup
	// ctx is cancelled by Stop to signal shutdown.
	ctx context.Context
	// cancel triggers that cancellation.
	cancel context.CancelFunc
	// stopMu guards taskChan against a send racing its close in Stop. Senders
	// hold it for reading, so any number may proceed at once; Stop takes it for
	// writing and therefore waits for all in-flight sends to finish first.
	stopMu sync.RWMutex
	// stopped records that the queue is closed, so Dispatch drops rather than
	// sends. It is read and written only under stopMu.
	stopped bool
}

// NewDispatcher constructs a dispatcher. A non-positive workerCount takes the
// default.
//
// The returned dispatcher is idle until Start is called.
func NewDispatcher(repo *Repository, encryptionKey string, workerCount int) *Dispatcher {
	if workerCount <= 0 {
		workerCount = defaultWorkerCount
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Dispatcher{
		repo:          repo,
		encryptionKey: encryptionKey,
		httpClient: &http.Client{
			Timeout: deliveryTimeout,
		},
		taskChan:    make(chan DispatchTask, taskQueueSize),
		workerCount: workerCount,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start launches the worker goroutines. Call it once, before any Dispatch.
func (d *Dispatcher) Start() {
	for i := 0; i < d.workerCount; i++ {
		d.wg.Add(1)
		go d.workerLoop(i)
	}
	log.Printf("[Webhook Dispatcher] Started %d async worker goroutines", d.workerCount)
}

// Stop closes the queue and waits for queued events to finish delivering.
//
// Events already enqueued are delivered rather than discarded, so a shutdown
// does not silently drop notifications the engine has accepted. Because each
// remaining event may still retry, this can block for the queue depth times the
// retry budget; callers should bound it with their own shutdown deadline.
//
// After Stop, Dispatch is a no-op. The dispatcher cannot be restarted.
func (d *Dispatcher) Stop() {
	d.cancel()

	// Closing under the write lock, after marking stopped, guarantees no
	// Dispatch is mid-send and none begins afterwards. Closing without this
	// would panic any request-path goroutine that happened to be enqueuing.
	d.stopMu.Lock()
	d.stopped = true
	close(d.taskChan)
	d.stopMu.Unlock()

	d.wg.Wait()
	log.Println("[Webhook Dispatcher] Worker pool shut down cleanly")
}

// Dispatch queues an event for background delivery and returns immediately.
//
// It never blocks and never fails: a full queue or a stopped dispatcher drops
// the event with a warning. Callers are on the request path and must not be
// delayed by webhook delivery, which is why there is no error to handle.
func (d *Dispatcher) Dispatch(tenantID, eventType string, data map[string]interface{}) {
	d.stopMu.RLock()
	defer d.stopMu.RUnlock()

	if d.stopped {
		log.Printf("[Webhook Dispatcher] Warning: dispatcher stopped, dropping event '%s' for tenant '%s'", eventType, tenantID)
		return
	}

	select {
	case d.taskChan <- DispatchTask{TenantID: tenantID, EventType: eventType, Data: data}:
	default:
		log.Printf("[Webhook Dispatcher] Warning: task buffer full, dropping event '%s' for tenant '%s'", eventType, tenantID)
	}
}

// workerLoop consumes tasks until the queue is closed and drained.
//
// Ranging over the channel is what makes shutdown orderly: the loop ends only
// once every buffered task has been handled.
func (d *Dispatcher) workerLoop(workerID int) {
	defer d.wg.Done()

	for task := range d.taskChan {
		d.processTask(task)
	}
}

// processTask resolves the endpoints subscribed to an event and delivers to
// each in turn.
//
// The payload is built once and shared across endpoints so that every
// subscriber sees the same event ID and timestamp, which is what lets them
// correlate and deduplicate. Failures are logged rather than returned: nothing
// is waiting on the result.
func (d *Dispatcher) processTask(task DispatchTask) {
	// A fresh context rather than the dispatcher's: work already accepted is
	// finished even as shutdown proceeds, and Stop waits for it.
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

// deliverToEndpoint posts a signed payload to one endpoint, retrying per
// retryBackoff, and records the outcome.
//
// The exact bytes signed are the exact bytes sent: the signature covers the
// serialised payload, so re-marshalling per attempt would invalidate it.
//
// Failures are recorded rather than returned. A delivery log entry is written
// whatever happens, since an endpoint that never receives anything is a
// question an operator has to be able to answer.
func (d *Dispatcher) deliverToEndpoint(ctx context.Context, ep *ent.WebhookEndpoint, eventType string, jsonBytes []byte, payloadObj EventData, timestamp int64) {
	// Secrets are stored encrypted, so each delivery decrypts the endpoint's
	// own. A failure here means the encryption key changed since the endpoint
	// was registered, and no signature can be produced.
	rawSecret, err := crypto.DecryptAES256GCM(ep.SecretKeyEncrypted, d.encryptionKey)
	if err != nil {
		log.Printf("[Webhook Dispatcher] Failed to decrypt secret for endpoint %s: %v", ep.ID, err)
		return
	}

	sig := SignPayload(rawSecret, timestamp, jsonBytes)
	sigHeader := FormatSignatureHeader(timestamp, sig)

	deliveryID := fmt.Sprintf("whd_%s", uuid.New().String()[:12])

	var statusCode int
	var respBodyStr string
	var lastErr error
	var isSuccess bool

	for attempt := 0; attempt < len(retryBackoff); attempt++ {
		if attempt > 0 {
			time.Sleep(retryBackoff[attempt])
		}

		// The request is rebuilt each attempt because its body reader is
		// consumed by the previous one.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(jsonBytes))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("X-Authn-Signature", sigHeader)
		req.Header.Set("X-Authn-Event", eventType)
		// The delivery ID stays constant across retries, so a subscriber can
		// recognise repeat attempts at the same delivery.
		req.Header.Set("X-Authn-Delivery", deliveryID)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		statusCode = resp.StatusCode
		// The response is read through a limit reader so a hostile or broken
		// endpoint cannot stream an unbounded body into memory.
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, responseSnippetBytes))
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

	payloadMap := map[string]interface{}{
		"id":        payloadObj.ID,
		"event":     payloadObj.EventType,
		"tenant_id": payloadObj.TenantID,
		"timestamp": payloadObj.Timestamp,
		"data":      payloadObj.Data,
	}

	_, _ = d.repo.CreateDelivery(ctx, ep.ID, eventType, payloadMap, statusCode, respBodyStr, errMsg, isSuccess)
}

// DeliverSync posts a single payload to one endpoint and returns the delivery
// record, blocking until it completes.
//
// This is the path behind the manual test ping and a redelivery, where an
// operator is waiting on the result and needs to see it. Unlike the queued
// path it does not retry: the operator can retry themselves, and a caller
// waiting on an HTTP response should not be held for the retry budget.
//
// Returns an error if the payload cannot be marshalled, the endpoint's secret
// cannot be decrypted, or the request cannot be built. A transport failure or
// an error status is not an error here — it is the result being reported, and
// is recorded in the returned delivery.
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
	req.Header.Set("User-Agent", userAgent)
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
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, responseSnippetBytes))
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
