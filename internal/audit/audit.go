/*
 * Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package audit emits access-decision events from the consent-filter plugin to
// an OpenTelemetry Collector as OTLP/HTTP log records. Each record carries a
// dedicated resource service.name so the Collector can route audit logs to a
// separate, append-only sink, cleanly apart from traces (see the OTEL section of
// doc/CONSENT_MANAGEMENT.md).
//
// Emission is asynchronous and best-effort: Emit never blocks the request path,
// events are batched by a background worker, and the queue drops (with a counter)
// when full - so a slow or absent Collector can never stall data access. The
// Collector plus its sink provide the durability/retention guarantees; the
// plugin -> Collector hop is buffered, at-most-once.
package audit

import (
	"bytes"
	"consent-plugin/internal/logging"
	"consent-plugin/internal/metrics"
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultServiceName is the resource service.name stamped on audit records when
// none is configured. It is the marker the Collector routes on to keep audit
// logs separate from ordinary telemetry.
const DefaultServiceName = "consent-access-audit"

// scopeName identifies the instrumentation that produced the records.
const scopeName = "consent-plugin/audit"

// otlpLogsPath is the OTLP/HTTP logs path appended to the configured base endpoint.
const otlpLogsPath = "/v1/logs"

// severityInfo is the OTLP severity number for an informational record (both
// allow and deny are normal decisions; the decision is carried as an attribute).
const severityInfo = 9

// Exporter tuning. The queue is bounded so a stalled Collector cannot grow memory
// without limit; excess events are dropped rather than blocking the request path.
const (
	defaultQueueSize     = 2048
	defaultBatchSize     = 64
	defaultFlushInterval = 2 * time.Second
	defaultTimeout       = 5 * time.Second
)

// Config configures an Emitter.
type Config struct {
	// Endpoint is the OTLP/HTTP base endpoint of the Collector (e.g.
	// http://otel-collector:4318); otlpLogsPath is appended unless already present.
	Endpoint string
	// ServiceName is the resource service.name stamped on every record (the
	// routing marker). Empty defaults to DefaultServiceName.
	ServiceName string
	// Timeout bounds a single export HTTP call. Zero defaults to defaultTimeout.
	Timeout time.Duration
	// Headers are extra HTTP headers sent on every export, for a Collector that
	// requires authentication (e.g. "Authorization" or a tenant header).
	Headers map[string]string
}

// key identifies the Emitter this configuration describes. Every field that
// changes the emitter's behaviour must appear in it: caching on endpoint and
// service name alone meant the first route's timeout and headers silently
// applied to every other route sharing them.
func (c Config) key() string {
	parts := make([]string, 0, 3+2*len(c.Headers))
	parts = append(parts, c.Endpoint, c.serviceName(), c.Timeout.String())
	for _, name := range sortedKeys(c.Headers) {
		parts = append(parts, name, c.Headers[name])
	}
	return strings.Join(parts, configKeySeparator)
}

// serviceName is the configured routing marker, or the default.
func (c Config) serviceName() string {
	if c.ServiceName == "" {
		return DefaultServiceName
	}
	return c.ServiceName
}

// configKeySeparator joins the parts of an emitter cache key. It cannot occur in
// a URL, a service name or a header value.
const configKeySeparator = "\x00"

// sortedKeys returns m's keys in a stable order, so an emitter key does not
// depend on map iteration order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Event is a single access decision to record.
type Event struct {
	// Time is when the decision was made.
	Time time.Time
	// RequestID correlates the record with the request (the Nginx $request_id).
	RequestID string
	// Subject is the data subject the decision was made for (the access-token sub).
	Subject string
	// Resource is the requested path.
	Resource string
	// Method is the HTTP method.
	Method string
	// Decision is "allow" or "deny".
	Decision string
	// Reason is a short human-readable explanation of the decision.
	Reason string
	// ConsentID is the consent an allow was matched on, so its receipt can be
	// fetched later by id. Empty on a deny; the attribute is then omitted.
	ConsentID string
}

// Emitter asynchronously exports audit Events as OTLP log records to a Collector.
type Emitter struct {
	endpoint    string
	serviceName string
	headers     map[string]string
	client      *http.Client
	queue       chan Event
	done        chan struct{}
	stopped     chan struct{}
	dropped     atomic.Uint64
	stopOnce    sync.Once
}

var (
	emittersMu sync.Mutex
	emitters   = map[string]*Emitter{}
)

func init() {
	// An attacker who can generate load can suppress the record of their own
	// access by filling the queue, so the loss must be alertable, not merely
	// logged every hundredth event.
	metrics.RegisterCounter(metrics.AuditDroppedCounter,
		"Audit events discarded because the export queue was full.",
		func() float64 { return float64(Dropped()) })
}

// Get returns a shared Emitter for cfg, creating (and starting) one on first use.
// Emitters are cached by the full configuration (see Config.key), so all routes
// exporting to the same Collector with the same settings share a single
// background worker and connection pool, while a route configuring a different
// timeout or different headers gets its own.
func Get(cfg Config) *Emitter {
	key := cfg.key()

	emittersMu.Lock()
	defer emittersMu.Unlock()
	if e := emitters[key]; e != nil {
		return e
	}
	e := newEmitter(cfg)
	emitters[key] = e
	return e
}

// ShutdownAll flushes and stops every emitter created so far.
//
// The runner is long-lived but not immortal: it is restarted on every redeploy,
// and without this up to defaultFlushInterval of access decisions were lost each
// time — silently, from the record that exists precisely to be complete. Wire it
// to SIGTERM/SIGINT.
func ShutdownAll() {
	emittersMu.Lock()
	pending := make([]*Emitter, 0, len(emitters))
	for _, e := range emitters {
		pending = append(pending, e)
	}
	emitters = map[string]*Emitter{}
	emittersMu.Unlock()

	for _, e := range pending {
		e.Shutdown()
	}
}

// newEmitter builds and starts an Emitter for cfg.
func newEmitter(cfg Config) *Emitter {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	serviceName := cfg.serviceName()
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if !strings.HasSuffix(endpoint, otlpLogsPath) {
		endpoint += otlpLogsPath
	}
	headers := make(map[string]string, len(cfg.Headers))
	for name, value := range cfg.Headers {
		headers[name] = value
	}
	e := &Emitter{
		endpoint:    endpoint,
		serviceName: serviceName,
		headers:     headers,
		client:      &http.Client{Timeout: timeout},
		queue:       make(chan Event, defaultQueueSize),
		done:        make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	go e.run()
	return e
}

// Emit queues ev for export. It never blocks: if the queue is full the event is
// dropped and a counter is incremented (data access must not wait on the audit
// pipe). Emit is safe for concurrent use.
//
// The reason is sanitised here rather than at the call site, so an upstream
// error body cannot reach the audit sink verbatim no matter which code path
// produced it.
func (e *Emitter) Emit(ev Event) {
	ev.Reason = SanitizeReason(ev.Reason)
	select {
	case e.queue <- ev:
	default:
		if n := e.dropped.Add(1); n%droppedLogEvery == 1 {
			logging.Warnf("audit queue full, dropping event (total dropped %d)", n)
		}
	}
}

// Dropped reports how many events this emitter has discarded because its queue
// was full. It is the signal that the record is incomplete: an attacker who can
// generate load can suppress the record of their own access, so this number must
// be observable rather than only logged every droppedLogEvery events.
func (e *Emitter) Dropped() uint64 {
	return e.dropped.Load()
}

// Dropped reports the total number of audit events discarded across every
// emitter.
func Dropped() uint64 {
	emittersMu.Lock()
	defer emittersMu.Unlock()
	var total uint64
	for _, e := range emitters {
		total += e.Dropped()
	}
	return total
}

// droppedLogEvery rate-limits the queue-full log line.
const droppedLogEvery = 100

// SanitizeReason makes a decision reason safe to export: control characters
// (including the newlines of an HTML or JSON error page) are collapsed to
// spaces, and the result is truncated.
//
// Reasons are built by wrapping dependency errors, and those errors embed the
// consent-manager's response body — which can carry identifiers or other
// personal data. Exporting it verbatim would push exactly the data the audit
// pipeline exists to keep controlled into the audit sink.
func SanitizeReason(reason string) string { return logging.Sanitize(reason) }

// Shutdown stops the background worker after flushing everything still queued.
// Intended for clean teardown and tests; the plugin runner is long-lived and
// normally never calls it.
func (e *Emitter) Shutdown() {
	e.stopOnce.Do(func() { close(e.done) })
	<-e.stopped
}

// run is the background worker: it batches queued events and exports them on a
// size or time trigger, and drains + flushes on shutdown.
func (e *Emitter) run() {
	defer close(e.stopped)
	batch := make([]Event, 0, defaultBatchSize)
	ticker := time.NewTicker(defaultFlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) > 0 {
			e.export(batch)
			batch = batch[:0]
		}
	}

	for {
		select {
		case ev := <-e.queue:
			batch = append(batch, ev)
			if len(batch) >= defaultBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-e.done:
			for {
				select {
				case ev := <-e.queue:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

// export POSTs a batch as an OTLP/HTTP logs payload. Failures are logged and
// dropped - audit export must not surface into the request path.
func (e *Emitter) export(batch []Event) {
	body, err := json.Marshal(e.buildPayload(batch))
	if err != nil {
		logging.Errorf("audit: failed to marshal %d event(s): %s", len(batch), logging.Sanitize(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		logging.Errorf("audit: failed to build the export request: %s", logging.Sanitize(err.Error()))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range e.headers {
		req.Header.Set(name, value)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		logging.ErrorfEvery("audit-export", "audit: export to %s failed: %s", e.endpoint, logging.Sanitize(err.Error()))
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= http.StatusMultipleChoices {
		logging.ErrorfEvery("audit-export-status", "audit: export to %s returned HTTP %d", e.endpoint, resp.StatusCode)
	}
}

// --- OTLP/HTTP JSON encoding (proto3 JSON mapping) --------------------------

type otlpPayload struct {
	ResourceLogs []resourceLogs `json:"resourceLogs"`
}

type resourceLogs struct {
	Resource  otlpResource `json:"resource"`
	ScopeLogs []scopeLogs  `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []keyValue `json:"attributes"`
}

type scopeLogs struct {
	Scope      instrumentationScope `json:"scope"`
	LogRecords []logRecord          `json:"logRecords"`
}

type instrumentationScope struct {
	Name string `json:"name"`
}

type logRecord struct {
	TimeUnixNano         string     `json:"timeUnixNano"`
	ObservedTimeUnixNano string     `json:"observedTimeUnixNano"`
	SeverityNumber       int        `json:"severityNumber"`
	SeverityText         string     `json:"severityText"`
	Body                 anyValue   `json:"body"`
	Attributes           []keyValue `json:"attributes"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

// anyValue is the OTLP AnyValue; only the string variant is used here.
type anyValue struct {
	StringValue string `json:"stringValue"`
}

// consentIDAttribute names the log attribute carrying Event.ConsentID.
const consentIDAttribute = "consent.id"

// buildPayload maps a batch of events to a single OTLP logs payload. The routing
// marker lives on the resource (service.name); the per-decision fields are log
// attributes using OpenTelemetry semantic-convention keys where they exist.
func (e *Emitter) buildPayload(batch []Event) otlpPayload {
	records := make([]logRecord, 0, len(batch))
	for _, ev := range batch {
		ts := strconv.FormatInt(ev.Time.UnixNano(), 10)
		attributes := []keyValue{
			{Key: "event.domain", Value: anyValue{StringValue: "audit"}},
			{Key: "event.name", Value: anyValue{StringValue: "consent.access.decision"}},
			{Key: "consent.decision", Value: anyValue{StringValue: ev.Decision}},
			{Key: "consent.reason", Value: anyValue{StringValue: ev.Reason}},
			{Key: "enduser.id", Value: anyValue{StringValue: ev.Subject}},
			{Key: "http.request.method", Value: anyValue{StringValue: ev.Method}},
			{Key: "url.path", Value: anyValue{StringValue: ev.Resource}},
			{Key: "http.request.id", Value: anyValue{StringValue: ev.RequestID}},
		}
		if ev.ConsentID != "" {
			attributes = append(attributes, keyValue{Key: consentIDAttribute, Value: anyValue{StringValue: ev.ConsentID}})
		}
		records = append(records, logRecord{
			TimeUnixNano:         ts,
			ObservedTimeUnixNano: ts,
			SeverityNumber:       severityInfo,
			SeverityText:         "INFO",
			Body:                 anyValue{StringValue: "consent access decision"},
			Attributes:           attributes,
		})
	}
	return otlpPayload{ResourceLogs: []resourceLogs{{
		Resource:  otlpResource{Attributes: []keyValue{{Key: "service.name", Value: anyValue{StringValue: e.serviceName}}}},
		ScopeLogs: []scopeLogs{{Scope: instrumentationScope{Name: scopeName}, LogRecords: records}},
	}}}
}
