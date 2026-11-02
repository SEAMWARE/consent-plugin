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

// Package metrics exposes the consent gate's operational signals in the
// Prometheus text format.
//
// A component that can deny production traffic had no counters at all: nothing
// said how many requests were allowed, denied or failed open, how long the
// consent-manager was taking, how large the request-context store had grown, or
// how many audit records had been dropped. Logs were the only signal, and they
// are unstructured and rate-limited. Operationally that is flying blind — a
// misconfigured route that denies everything looks exactly like a quiet one.
//
// The exporter is hand-rolled rather than pulling in a Prometheus client, for
// the same reason the OTLP encoder is: this is a sidecar-adjacent plugin whose
// dependency tree is part of its risk surface, and the text format is small.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metric names. The consent_ prefix keeps them together in a shared registry.
const (
	decisionsMetric             = "consent_decisions_total"
	dependencyCallsMetric       = "consent_dependency_calls_total"
	dependencyLatency           = "consent_dependency_duration_seconds"
	purposeUnconstrainedMetric  = "consent_purpose_unconstrained_total"
	contractUnconstrainedMetric = "consent_contract_unconstrained_total"
	contextStoreSizeMetric      = "consent_request_context_store_size"
	contextEvictedMetric        = "consent_request_contexts_evicted_total"
	auditDroppedMetric          = "consent_audit_events_dropped_total"
)

// Dependency names used as the "dependency" label.
const (
	DependencyConsentManager = "consent_manager"
	DependencyOwnerResolver  = "owner_resolver"
)

// Call outcomes used as the "outcome" label.
const (
	OutcomeSuccess = "success"
	OutcomeError   = "error"
)

// latencyBuckets are the histogram's upper bounds in seconds. They straddle the
// default per-call timeout (5s) so a dependency drifting toward it is visible
// before it starts failing.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

var (
	mu sync.Mutex

	// decisions counts enforced decisions by decision and by the fail mode that
	// produced them, so "denied because no consent" and "denied because the
	// consent-manager was down" are distinguishable — they mean opposite things
	// operationally.
	decisions = map[labelPair]uint64{}

	// dependencyCalls counts outbound calls by dependency and outcome.
	dependencyCalls = map[labelPair]uint64{}

	// latency holds one histogram per dependency.
	latency = map[string]*histogram{}

	// purposeUnconstrained counts consent checks run without a processing
	// purpose to match against, i.e. checks where half of the consumer/purpose
	// scoping was not actually applied.
	purposeUnconstrained uint64

	// contractUnconstrained counts consent checks run with neither a contract nor
	// a privacy notice to scope them.
	contractUnconstrained uint64

	// callbacks are read at scrape time from whoever owns the number, so this
	// package never has to be told when a store's size changes.
	callbackMu sync.Mutex
	callbacks  = map[string]callbackMetric{}
)

// Prometheus metric types used in the exposition.
const (
	metricTypeCounter = "counter"
	metricTypeGauge   = "gauge"
)

// callbackMetric is a value this package does not own, read at scrape time.
type callbackMetric struct {
	help string
	kind string
	read func() float64
}

// labelPair is a two-label metric key.
type labelPair struct{ first, second string }

// histogram is a cumulative-bucket histogram.
type histogram struct {
	counts []uint64
	sum    float64
	total  uint64
}

// observe records one value.
func (h *histogram) observe(value float64) {
	for i, bound := range latencyBuckets {
		if value <= bound {
			h.counts[i]++
		}
	}
	h.sum += value
	h.total++
}

// RecordDecision counts one enforced access decision. failMode names why the
// decision could not be made normally ("" for an ordinary consent verdict), so
// a deny caused by an outage is not confused with a deny caused by consent.
func RecordDecision(decision, failMode string) {
	if failMode == "" {
		failMode = "none"
	}
	mu.Lock()
	defer mu.Unlock()
	decisions[labelPair{decision, failMode}]++
}

// RecordDependencyCall records one outbound call to a dependency: its outcome
// and how long it took.
func RecordDependencyCall(dependency, outcome string, duration time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	dependencyCalls[labelPair{dependency, outcome}]++
	h := latency[dependency]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(latencyBuckets))}
		latency[dependency] = h
	}
	h.observe(duration.Seconds())
}

// RecordPurposeUnconstrained counts one consent check made without a processing
// purpose to scope it.
//
// Purpose matching depends on the OwnerResolver populating an optional field. A
// resolver whose rules never set it leaves purpose scoping entirely disabled,
// which is a silent narrowing of a compliance property — a consent granted for
// one purpose then authorises release for any other. This makes that state
// visible and alertable instead of merely documented.
func RecordPurposeUnconstrained() {
	mu.Lock()
	defer mu.Unlock()
	purposeUnconstrained++
}

// RecordContractUnconstrained counts one consent check made with neither a
// contractUri nor a privacy notice id, so any consent from this owner to this
// consumer under this provider matches. Alert on it before enabling require_contract.
func RecordContractUnconstrained() {
	mu.Lock()
	defer mu.Unlock()
	contractUnconstrained++
}

// RegisterGauge publishes a value that can go up and down, read at scrape time.
// The owner of the number keeps owning it; this package only asks for it.
func RegisterGauge(name, help string, read func() float64) {
	registerCallback(name, help, metricTypeGauge, read)
}

// RegisterCounter publishes a monotonically increasing value, read at scrape
// time.
//
// The distinction from RegisterGauge is not cosmetic: a `_total` series declared
// as a gauge makes `promtool check metrics` complain, and anyone reaching for
// `rate(..._total[5m])` over it is relying on an accident rather than on a
// stated contract.
func RegisterCounter(name, help string, read func() float64) {
	registerCallback(name, help, metricTypeCounter, read)
}

// registerCallback records a scrape-time value of the given Prometheus type.
func registerCallback(name, help, kind string, read func() float64) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	callbacks[name] = callbackMetric{help: help, kind: kind, read: read}
}

// Handler serves the metrics in the Prometheus text exposition format.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if _, err := w.Write([]byte(render())); err != nil {
			// Nothing useful to do: the scraper went away mid-write.
			return
		}
	})
}

// render produces the full exposition payload.
func render() string {
	var out strings.Builder

	mu.Lock()
	writeCounter(&out, decisionsMetric, "Access decisions enforced, by decision and fail mode.",
		"decision", "fail_mode", decisions)
	writeCounter(&out, dependencyCallsMetric, "Outbound calls to a dependency, by outcome.",
		"dependency", "outcome", dependencyCalls)

	fmt.Fprintf(&out, "# HELP %s Consent checks run without a processing purpose to scope them.\n", purposeUnconstrainedMetric)
	fmt.Fprintf(&out, "# TYPE %s counter\n", purposeUnconstrainedMetric)
	fmt.Fprintf(&out, "%s %d\n", purposeUnconstrainedMetric, purposeUnconstrained)

	fmt.Fprintf(&out, "# HELP %s Consent checks run without a contract or privacy notice to scope them.\n", contractUnconstrainedMetric)
	fmt.Fprintf(&out, "# TYPE %s counter\n", contractUnconstrainedMetric)
	fmt.Fprintf(&out, "%s %d\n", contractUnconstrainedMetric, contractUnconstrained)

	fmt.Fprintf(&out, "# HELP %s Duration of outbound dependency calls in seconds.\n", dependencyLatency)
	fmt.Fprintf(&out, "# TYPE %s histogram\n", dependencyLatency)
	for _, dependency := range sortedMapKeys(latency) {
		h := latency[dependency]
		for i, bound := range latencyBuckets {
			// counts is already cumulative: observe increments every bucket whose
			// bound is at or above the value.
			fmt.Fprintf(&out, "%s_bucket{dependency=%q,le=%q} %d\n",
				dependencyLatency, dependency, strconv.FormatFloat(bound, 'g', -1, 64), h.counts[i])
		}
		fmt.Fprintf(&out, "%s_bucket{dependency=%q,le=\"+Inf\"} %d\n", dependencyLatency, dependency, h.total)
		fmt.Fprintf(&out, "%s_sum{dependency=%q} %s\n", dependencyLatency, dependency, strconv.FormatFloat(h.sum, 'g', -1, 64))
		fmt.Fprintf(&out, "%s_count{dependency=%q} %d\n", dependencyLatency, dependency, h.total)
	}
	mu.Unlock()

	callbackMu.Lock()
	names := make([]string, 0, len(callbacks))
	for name := range callbacks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		metric := callbacks[name]
		fmt.Fprintf(&out, "# HELP %s %s\n", name, metric.help)
		fmt.Fprintf(&out, "# TYPE %s %s\n", name, metric.kind)
		fmt.Fprintf(&out, "%s %s\n", name, strconv.FormatFloat(metric.read(), 'g', -1, 64))
	}
	callbackMu.Unlock()

	return out.String()
}

// writeCounter renders one two-label counter family in a stable order.
func writeCounter(out *strings.Builder, name, help, firstLabel, secondLabel string, values map[labelPair]uint64) {
	fmt.Fprintf(out, "# HELP %s %s\n", name, help)
	fmt.Fprintf(out, "# TYPE %s counter\n", name)
	keys := make([]labelPair, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].first != keys[j].first {
			return keys[i].first < keys[j].first
		}
		return keys[i].second < keys[j].second
	})
	for _, key := range keys {
		fmt.Fprintf(out, "%s{%s=%q,%s=%q} %d\n", name, firstLabel, key.first, secondLabel, key.second, values[key])
	}
}

// sortedMapKeys returns a map's keys in a stable order.
func sortedMapKeys(m map[string]*histogram) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Metric names published by the rest of the plugin through RegisterGauge and
// RegisterCounter.
const (
	// ContextStoreSizeGauge tracks in-flight gated requests. It goes up and down,
	// so it is a gauge: in a healthy runner it returns to zero when idle, and a
	// floor that keeps rising is the leak.
	ContextStoreSizeGauge = contextStoreSizeMetric

	// ContextEvictedCounter counts contexts dropped because they expired or the
	// store was full — requests that never reached their response phase. It only
	// increases, so it is a counter.
	ContextEvictedCounter = contextEvictedMetric

	// AuditDroppedCounter counts audit records lost to a full queue. An attacker
	// who can generate load can suppress the record of their own access, so this
	// must be alertable. It only increases, so it is a counter.
	AuditDroppedCounter = auditDroppedMetric
)

// Reset clears every metric. For tests.
func Reset() {
	mu.Lock()
	decisions = map[labelPair]uint64{}
	dependencyCalls = map[labelPair]uint64{}
	latency = map[string]*histogram{}
	purposeUnconstrained = 0
	contractUnconstrained = 0
	mu.Unlock()

	callbackMu.Lock()
	callbacks = map[string]callbackMetric{}
	callbackMu.Unlock()
}
