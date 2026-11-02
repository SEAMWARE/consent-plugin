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

// Package consent provides an HTTP client for the dsc-consent-manager, which
// records whether a data owner has granted the consuming participant consent to
// access their personal data. The verdict is coarse — allow or deny
// for the whole response — and is enforced by the plugin's response phase.
package consent

// Decision represents the consent-manager's verdict on one data owner.
// It determines how the plugin handles the upstream response.
type Decision string

// Decision constants define the possible consent verdicts.
const (
	// DecisionAllow indicates the response should pass through unmodified.
	DecisionAllow Decision = "allow"

	// DecisionDeny indicates the response should be blocked entirely,
	// returning a configured error status and body to the client.
	DecisionDeny Decision = "deny"
)

// Mode selects how a ConsentRequest is checked against the consent-manager.
type Mode string

// Mode constants. Their values equal the plugin's check_mode values, so a validated
// config value converts directly. An unset Mode is list mode; any other value denies.
const (
	// ModeList pages through GET /consents?userIdentifier= and matches each record.
	ModeList Mode = "list"

	// ModeCheck asks GET /consents/check and then reads the named consent to
	// match it. It requires PrivacyNoticeID.
	ModeCheck Mode = "check"
)

// ConsentRequest is one consent question: may this consumer be given this data
// owner's data, for this purpose and resource?
type ConsentRequest struct {
	// Subject is the DATA OWNER whose consent decides the access — resolved from
	// the response payload by the OwnerResolver. It is never the requestor.
	Subject string `json:"subject"`

	// Resource is the request path being accessed (e.g., "/api/v1/users/123").
	Resource string `json:"resource"`

	// Method is the HTTP method of the original request (e.g., "GET", "POST").
	Method string `json:"method"`

	// DataResource is the resource the owner was resolved for. It is recorded for
	// audit only: a consent's data[] holds notice categories, not resource ids.
	DataResource string `json:"data_resource,omitempty"`

	// Mode selects list or check mode; the zero value is list mode.
	Mode Mode `json:"mode,omitempty"`

	// PrivacyNoticeID, when set, scopes the check to consents decided against
	// this notice (a UUID). Check mode requires it.
	PrivacyNoticeID string `json:"privacy_notice_id,omitempty"`

	// ContractURI, when set, scopes the check to consents under this contract.
	ContractURI string `json:"contract_uri,omitempty"`

	// Consumer identifies the participant the data is being released TO, as its
	// participant identifier (DID). It is REQUIRED: a consent is an agreement between a
	// data subject and one named consumer for one named purpose, so a check that
	// ignores it would let participant Y ride on a consent the subject granted to
	// participant X. A check without a consumer is denied.
	Consumer string `json:"consumer,omitempty"`

	// Purpose, when set, further scopes the check to the processing purpose the
	// exchange is governed by: a consent counts only if its purposes[] contains
	// it verbatim. Empty means the purpose is not known — the consumer match
	// still applies.
	Purpose string `json:"purpose,omitempty"`
}

// ConsentResponse is the verdict for one ConsentRequest.
type ConsentResponse struct {
	// Decision is the consent verdict: "allow" or "deny".
	Decision Decision `json:"decision"`

	// Reason is a human-readable explanation for the consent decision,
	// recorded in the audit log and useful for debugging.
	Reason string `json:"reason,omitempty"`

	// ConsentID is the matched consent on an allow, so its receipt can be fetched later.
	ConsentID string `json:"consent_id,omitempty"`
}
