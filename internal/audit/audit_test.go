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

package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmitExportsOTLPLog verifies an emitted event is exported to the Collector's
// /v1/logs endpoint as an OTLP log record carrying the routing service.name on
// the resource and the decision fields as attributes.
func TestEmitExportsOTLPLog(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newEmitter(Config{Endpoint: srv.URL, ServiceName: "consent-access-audit"})
	e.Emit(Event{
		Time:      time.Unix(0, 1700000000000000000),
		RequestID: "req-1",
		Subject:   "did:key:zTest",
		Resource:  "/ngsi-ld/v1/entities/x",
		Method:    "GET",
		Decision:  "deny",
		Reason:    "no granted consent",
	})
	e.Shutdown()

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodies, 1)
	assert.Equal(t, otlpLogsPath, paths[0], "must POST to the OTLP logs path")

	var p otlpPayload
	require.NoError(t, json.Unmarshal(bodies[0], &p))
	require.Len(t, p.ResourceLogs, 1)

	// routing marker: service.name on the resource
	resAttrs := p.ResourceLogs[0].Resource.Attributes
	require.Len(t, resAttrs, 1)
	assert.Equal(t, "service.name", resAttrs[0].Key)
	assert.Equal(t, "consent-access-audit", resAttrs[0].Value.StringValue)

	require.Len(t, p.ResourceLogs[0].ScopeLogs, 1)
	assert.Equal(t, scopeName, p.ResourceLogs[0].ScopeLogs[0].Scope.Name)
	recs := p.ResourceLogs[0].ScopeLogs[0].LogRecords
	require.Len(t, recs, 1)
	assert.Equal(t, "1700000000000000000", recs[0].TimeUnixNano, "int64 nanos must be a JSON string")

	attrs := map[string]string{}
	for _, a := range recs[0].Attributes {
		attrs[a.Key] = a.Value.StringValue
	}
	assert.Equal(t, "audit", attrs["event.domain"])
	assert.Equal(t, "consent.access.decision", attrs["event.name"])
	assert.Equal(t, "deny", attrs["consent.decision"])
	assert.Equal(t, "no granted consent", attrs["consent.reason"])
	assert.Equal(t, "did:key:zTest", attrs["enduser.id"])
	assert.Equal(t, "GET", attrs["http.request.method"])
	assert.Equal(t, "/ngsi-ld/v1/entities/x", attrs["url.path"])
	assert.Equal(t, "req-1", attrs["http.request.id"])
}

// TestConsentIDAttribute verifies an allow carries the matched consent id and a
// record without one omits the attribute rather than exporting an empty value.
func TestConsentIDAttribute(t *testing.T) {
	tests := []struct {
		name      string
		consentID string
		wantFound bool
	}{
		{name: "matched consent", consentID: "3f1e2d4c-5b6a-4789-8abc-def012345678", wantFound: true},
		{name: "no consent", consentID: "", wantFound: false},
	}
	e := newEmitter(Config{Endpoint: "http://127.0.0.1:0"})
	defer e.Shutdown()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := e.buildPayload([]Event{{Decision: "allow", ConsentID: tt.consentID}})
			value, found := "", false
			for _, a := range p.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes {
				if a.Key == consentIDAttribute {
					value, found = a.Value.StringValue, true
				}
			}
			assert.Equal(t, tt.wantFound, found)
			assert.Equal(t, tt.consentID, value)
		})
	}
}

// TestEndpointNormalization verifies the base endpoint gets /v1/logs appended and
// an endpoint already ending in /v1/logs is left untouched.
func TestEndpointNormalization(t *testing.T) {
	assert.Equal(t, "http://c:4318/v1/logs", newEmitter(Config{Endpoint: "http://c:4318"}).endpoint)
	assert.Equal(t, "http://c:4318/v1/logs", newEmitter(Config{Endpoint: "http://c:4318/"}).endpoint)
	assert.Equal(t, "http://c:4318/v1/logs", newEmitter(Config{Endpoint: "http://c:4318/v1/logs"}).endpoint)
}

// TestEmitNeverBlocksWhenQueueFull verifies Emit drops (and counts) events rather
// than blocking the caller when the queue is full and nothing is draining it.
func TestEmitNeverBlocksWhenQueueFull(t *testing.T) {
	e := &Emitter{
		endpoint:    "http://unused/v1/logs",
		serviceName: "x",
		client:      &http.Client{},
		queue:       make(chan Event, 2),
		done:        make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	// no worker draining the queue
	for i := 0; i < 10; i++ {
		e.Emit(Event{})
	}
	assert.GreaterOrEqual(t, e.dropped.Load(), uint64(8), "overflow beyond the queue capacity must be dropped")
}

// TestGetDistinguishesConfigurations verifies the emitter cache keys on the full
// configuration. Keying on endpoint + service name alone meant whichever route
// created the emitter first silently imposed its timeout and headers on every
// other route sharing that Collector.
func TestGetDistinguishesConfigurations(t *testing.T) {
	base := Config{Endpoint: "http://collector:4318", ServiceName: "audit", Timeout: time.Second}

	tests := []struct {
		name   string
		mutate func(cfg *Config)
	}{
		{"endpoint", func(cfg *Config) { cfg.Endpoint = "http://other:4318" }},
		{"service name", func(cfg *Config) { cfg.ServiceName = "other-audit" }},
		{"timeout", func(cfg *Config) { cfg.Timeout = 5 * time.Second }},
		{"headers", func(cfg *Config) { cfg.Headers = map[string]string{"Authorization": "Bearer x"} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := base
			tt.mutate(&other)
			assert.NotEqual(t, base.key(), other.key(),
				"configurations differing in %s must not share an emitter", tt.name)
		})
	}

	t.Run("header order does not matter", func(t *testing.T) {
		a := base
		a.Headers = map[string]string{"A": "1", "B": "2"}
		b := base
		b.Headers = map[string]string{"B": "2", "A": "1"}
		assert.Equal(t, a.key(), b.key())
	})

	t.Run("an unnamed service falls back to the default", func(t *testing.T) {
		named := Config{Endpoint: "http://collector:4318", ServiceName: DefaultServiceName}
		unnamed := Config{Endpoint: "http://collector:4318"}
		assert.Equal(t, named.key(), unnamed.key())
	})
}

// TestEmitSendsConfiguredHeaders verifies extra headers reach the Collector, so
// an authenticating audit sink can be used.
func TestEmitSendsConfiguredHeaders(t *testing.T) {
	received := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newEmitter(Config{Endpoint: srv.URL, Headers: map[string]string{"Authorization": "Bearer audit-token"}})
	e.Emit(Event{Time: time.Now(), Decision: "allow"})
	e.Shutdown()

	select {
	case h := <-received:
		assert.Equal(t, "Bearer audit-token", h.Get("Authorization"))
		assert.Equal(t, "application/json", h.Get("Content-Type"))
	case <-time.After(time.Second):
		t.Fatal("the Collector never received an export")
	}
}

// TestEmitSanitizesReason verifies the sanitisation happens on the way out, so
// no call site can bypass it.
func TestEmitSanitizesReason(t *testing.T) {
	received := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newEmitter(Config{Endpoint: srv.URL})
	e.Emit(Event{Time: time.Now(), Decision: "deny", Reason: "upstream said:\n{\"email\":\"alice@example.org\"}"})
	e.Shutdown()

	select {
	case body := <-received:
		assert.NotContains(t, string(body), `\n`, "control characters must not reach the sink")
		assert.Contains(t, string(body), "upstream said: ")
	case <-time.After(time.Second):
		t.Fatal("the Collector never received an export")
	}
}

// TestShutdownAllFlushesEveryEmitter verifies a termination flush drains all
// emitters, so a redeploy does not silently discard queued decisions.
func TestShutdownAllFlushesEveryEmitter(t *testing.T) {
	var mu sync.Mutex
	var records int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload otlpPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		for _, rl := range payload.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				records += len(sl.LogRecords)
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	for _, serviceName := range []string{"audit-a", "audit-b"} {
		Get(Config{Endpoint: srv.URL, ServiceName: serviceName}).
			Emit(Event{Time: time.Now(), Decision: "allow", Subject: serviceName})
	}

	ShutdownAll()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, records, "every emitter's queue must be flushed on shutdown")
}

// TestDroppedIsObservable verifies the drop counter is exposed. An attacker who
// can generate load can suppress the record of their own access, so the fact
// that records were lost must be visible, not only logged occasionally.
func TestDroppedIsObservable(t *testing.T) {
	e := &Emitter{queue: make(chan Event, 1), done: make(chan struct{}), stopped: make(chan struct{})}
	close(e.stopped) // no worker: nothing drains the queue

	for i := 0; i < 5; i++ {
		e.Emit(Event{Time: time.Now(), Decision: "allow"})
	}

	assert.Equal(t, uint64(4), e.Dropped(), "one event fits the queue, the rest are dropped and counted")
}

// TestDroppedAggregatesAcrossEmitters verifies the package-level Dropped — the
// value the registered metric callback reads, and therefore the only thing that
// makes suppression of an access record visible — sums every emitter.
func TestDroppedAggregatesAcrossEmitters(t *testing.T) {
	ShutdownAll() // start from a clean registry
	t.Cleanup(ShutdownAll)

	assert.Zero(t, Dropped(), "a fresh registry has dropped nothing")

	// Two emitters whose workers are already stopped, so nothing drains them.
	for _, serviceName := range []string{"audit-a", "audit-b"} {
		e := Get(Config{Endpoint: "http://collector.invalid:4318", ServiceName: serviceName})
		e.Shutdown()
		for i := 0; i < defaultQueueSize+3; i++ {
			e.Emit(Event{Time: time.Now(), Decision: "allow"})
		}
	}

	assert.Equal(t, uint64(6), Dropped(),
		"three events past the queue size are dropped by each of the two emitters")
}
