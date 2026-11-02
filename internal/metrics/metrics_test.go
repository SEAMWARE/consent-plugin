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

package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRenderExposition covers the whole payload: counters with their labels, the
// histogram's cumulative buckets, and gauges read at scrape time.
func TestRenderExposition(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	RecordDecision("allow", "")
	RecordDecision("allow", "")
	RecordDecision("deny", "")
	// A deny caused by an outage must be distinguishable from a deny caused by
	// consent: they mean opposite things operationally.
	RecordDecision("deny", "by_policy")

	RecordDependencyCall(DependencyConsentManager, OutcomeSuccess, 20*time.Millisecond)
	RecordDependencyCall(DependencyConsentManager, OutcomeError, 3*time.Second)

	RecordPurposeUnconstrained()
	RecordContractUnconstrained()
	RecordContractUnconstrained()

	RegisterGauge(ContextStoreSizeGauge, "Request contexts currently held.", func() float64 { return 7 })
	RegisterCounter(ContextEvictedCounter, "Request contexts evicted.", func() float64 { return 3 })

	out := render()

	assert.Contains(t, out, `consent_decisions_total{decision="allow",fail_mode="none"} 2`)
	assert.Contains(t, out, `consent_decisions_total{decision="deny",fail_mode="none"} 1`)
	assert.Contains(t, out, `consent_decisions_total{decision="deny",fail_mode="by_policy"} 1`)

	assert.Contains(t, out, `consent_dependency_calls_total{dependency="consent_manager",outcome="success"} 1`)
	assert.Contains(t, out, `consent_dependency_calls_total{dependency="consent_manager",outcome="error"} 1`)

	// 20ms falls in the 0.025 bucket, 3s does not; both are under +Inf.
	assert.Contains(t, out, `consent_dependency_duration_seconds_bucket{dependency="consent_manager",le="0.025"} 1`)
	assert.Contains(t, out, `consent_dependency_duration_seconds_bucket{dependency="consent_manager",le="5"} 2`)
	assert.Contains(t, out, `consent_dependency_duration_seconds_bucket{dependency="consent_manager",le="+Inf"} 2`)
	assert.Contains(t, out, `consent_dependency_duration_seconds_count{dependency="consent_manager"} 2`)

	assert.Contains(t, out, "consent_purpose_unconstrained_total 1")
	assert.Contains(t, out, "consent_contract_unconstrained_total 2")
	assert.Contains(t, out, "# TYPE consent_contract_unconstrained_total counter")

	assert.Contains(t, out, "consent_request_context_store_size 7")
	assert.Contains(t, out, "# TYPE consent_decisions_total counter")
	assert.Contains(t, out, "# TYPE consent_dependency_duration_seconds histogram")

	// A `_total` series must be declared a counter, or `rate()` over it is an
	// accident rather than a contract; and every family needs a HELP line.
	assert.Contains(t, out, "# TYPE consent_request_context_store_size gauge")
	assert.Contains(t, out, "# TYPE consent_request_contexts_evicted_total counter")
	assert.Contains(t, out, "# HELP consent_request_context_store_size Request contexts currently held.")
	assert.Contains(t, out, "# HELP consent_request_contexts_evicted_total Request contexts evicted.")
}

// TestGaugesAreReadAtScrapeTime verifies a gauge reflects the current value
// rather than the one at registration — the store size is the point.
func TestGaugesAreReadAtScrapeTime(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	size := 0
	RegisterGauge(ContextStoreSizeGauge, "Request contexts currently held.", func() float64 { return float64(size) })

	assert.Contains(t, render(), "consent_request_context_store_size 0")
	size = 42
	assert.Contains(t, render(), "consent_request_context_store_size 42")
}

// TestHandlerServesExposition verifies the HTTP surface and its content type.
func TestHandlerServesExposition(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	RecordDecision("deny", "always_closed")

	recorder := httptest.NewRecorder()
	Handler().ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, recorder.Body.String(), `consent_decisions_total{decision="deny",fail_mode="always_closed"} 1`)
}

// TestRenderIsStable verifies the output order does not depend on map iteration,
// so a scrape diff reflects real change.
func TestRenderIsStable(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	for _, decision := range []string{"deny", "allow"} {
		RecordDecision(decision, "")
	}
	RecordDependencyCall(DependencyOwnerResolver, OutcomeSuccess, time.Millisecond)
	RecordDependencyCall(DependencyConsentManager, OutcomeSuccess, time.Millisecond)
	RegisterCounter(AuditDroppedCounter, "Audit events dropped.", func() float64 { return 1 })
	RegisterGauge(ContextStoreSizeGauge, "Request contexts currently held.", func() float64 { return 2 })

	first := render()
	for i := 0; i < 20; i++ {
		assert.Equal(t, first, render())
	}
}
