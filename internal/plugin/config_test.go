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

package plugin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validConfigJSON returns a minimal valid configuration JSON for testing.
func validConfigJSON() map[string]interface{} {
	return map[string]interface{}{
		"consent_api_url":    "https://consent.example.com/api",
		"owner_resolver_url": "https://owner-resolver.example.com/resolve",
		"token_service_url":  "https://consent-facade.example.com/internal/tokens",
	}
}

// toJSON marshals a map to JSON bytes for test inputs.
func toJSON(t *testing.T, m map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, cfg *Config)
	}{
		{
			name:  "valid config with only required field applies defaults",
			input: []byte(`{"consent_api_url": "https://consent.example.com/api", "owner_resolver_url": "https://owner-resolver.example.com/resolve", "token_service_url": "https://facade.example.com/internal/tokens"}`),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "https://consent.example.com/api", cfg.ConsentAPIURL)
				assert.Equal(t, DefaultConsentAPITimeout, cfg.ConsentAPITimeout)
				assert.Equal(t, DefaultJWTHeaderName, cfg.JWTHeaderName)
				assert.Equal(t, DefaultDenyStatusCode, cfg.DenyStatusCode)
				assert.Equal(t, DefaultDenyResponseBody, cfg.DenyResponseBody)
				assert.Equal(t, DefaultDenyResponseContentType, cfg.DenyResponseContentType)
				assert.Nil(t, cfg.JWTClaimsToForward)
				assert.Equal(t, CheckModeList, cfg.CheckMode)
				assert.False(t, cfg.RequireContract)
			},
		},
		{
			name: "valid config with all fields set",
			input: func() []byte {
				m := map[string]interface{}{
					"consent_api_url":            "http://localhost:8080/consent",
					"owner_resolver_url":         "http://localhost:9090/resolve",
					"participant_token":          "static-token",
					"consent_api_timeout":        10000,
					"jwt_header_name":            "X-Auth-Token",
					"jwt_claims_to_forward":      []string{"sub", "scope", "aud"},
					"deny_status_code":           451,
					"deny_response_body":         `{"msg":"blocked"}`,
					"deny_response_content_type": "text/plain",
				}
				b, _ := json.Marshal(m)
				return b
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "http://localhost:8080/consent", cfg.ConsentAPIURL)
				assert.Equal(t, "http://localhost:9090/resolve", cfg.OwnerResolverURL)
				assert.Equal(t, 10000, cfg.ConsentAPITimeout)
				assert.Equal(t, "X-Auth-Token", cfg.JWTHeaderName)
				assert.Equal(t, []string{"sub", "scope", "aud"}, cfg.JWTClaimsToForward)
				assert.Equal(t, 451, cfg.DenyStatusCode)
				assert.Equal(t, `{"msg":"blocked"}`, cfg.DenyResponseBody)
				assert.Equal(t, "text/plain", cfg.DenyResponseContentType)
			},
		},
		{
			name:      "empty input returns error",
			input:     nil,
			wantErr:   true,
			errSubstr: "input is empty",
		},
		{
			name:      "empty byte slice returns error",
			input:     []byte{},
			wantErr:   true,
			errSubstr: "input is empty",
		},
		{
			name:      "invalid JSON returns error",
			input:     []byte(`{not json}`),
			wantErr:   true,
			errSubstr: "failed to unmarshal JSON",
		},
		{
			name:      "missing consent_api_url returns error",
			input:     []byte(`{"consent_api_timeout": 3000}`),
			wantErr:   true,
			errSubstr: "consent_api_url is required",
		},
		{
			name:      "empty consent_api_url returns error",
			input:     []byte(`{"consent_api_url": ""}`),
			wantErr:   true,
			errSubstr: "consent_api_url is required",
		},
		{
			name:      "invalid URL for consent_api_url returns error",
			input:     []byte(`{"consent_api_url": "not-a-url"}`),
			wantErr:   true,
			errSubstr: "not a valid URL",
		},
		{
			name:      "non-http scheme in consent_api_url returns error",
			input:     []byte(`{"consent_api_url": "ftp://consent.example.com"}`),
			wantErr:   true,
			errSubstr: "must use http or https scheme",
		},
		{
			name: "consent_api_timeout below minimum returns error",
			input: func() []byte {
				m := validConfigJSON()
				m["consent_api_timeout"] = -1
				return toJSON(t, m)
			}(),
			wantErr:   true,
			errSubstr: "consent_api_timeout must be between",
		},
		{
			name: "consent_api_timeout above maximum returns error",
			input: func() []byte {
				m := validConfigJSON()
				m["consent_api_timeout"] = 70000
				return toJSON(t, m)
			}(),
			wantErr:   true,
			errSubstr: "consent_api_timeout must be between",
		},
		{
			name: "deny_status_code below minimum returns error",
			input: func() []byte {
				m := validConfigJSON()
				m["deny_status_code"] = 50
				return toJSON(t, m)
			}(),
			wantErr:   true,
			errSubstr: "deny_status_code must be between",
		},
		{
			name: "deny_status_code above maximum returns error",
			input: func() []byte {
				m := validConfigJSON()
				m["deny_status_code"] = 600
				return toJSON(t, m)
			}(),
			wantErr:   true,
			errSubstr: "deny_status_code must be between",
		},
		{
			name: "consent_api_timeout at minimum boundary is valid",
			input: func() []byte {
				m := validConfigJSON()
				m["consent_api_timeout"] = MinConsentAPITimeout
				return toJSON(t, m)
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, MinConsentAPITimeout, cfg.ConsentAPITimeout)
			},
		},
		{
			name: "consent_api_timeout at maximum boundary is valid",
			input: func() []byte {
				m := validConfigJSON()
				m["consent_api_timeout"] = MaxConsentAPITimeout
				return toJSON(t, m)
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, MaxConsentAPITimeout, cfg.ConsentAPITimeout)
			},
		},
		{
			name: "deny_status_code at boundaries is valid",
			input: func() []byte {
				m := validConfigJSON()
				m["deny_status_code"] = MinHTTPStatusCode
				return toJSON(t, m)
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, MinHTTPStatusCode, cfg.DenyStatusCode)
			},
		},
		{
			name: "empty jwt_claims_to_forward is valid",
			input: func() []byte {
				m := validConfigJSON()
				m["jwt_claims_to_forward"] = []string{}
				return toJSON(t, m)
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Empty(t, cfg.JWTClaimsToForward)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				assert.Nil(t, cfg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

// TestParseConfig_EnvFallback verifies the credential-bearing fields fall back to
// their env vars when omitted from the route config, and that a value in the
// config always takes precedence over the env var.
func TestParseConfig_EnvFallback(t *testing.T) {
	t.Run("env fills empty fields", func(t *testing.T) {
		t.Setenv(EnvTokenServiceURL, "http://facade-from-env:8080/internal/tokens")

		in := validConfigJSON()
		delete(in, "token_service_url") // so the env var is the only source
		cfg, err := ParseConfig(toJSON(t, in))
		require.NoError(t, err)
		assert.Equal(t, "http://facade-from-env:8080/internal/tokens", cfg.TokenServiceURL)
	})

	t.Run("config values win over env", func(t *testing.T) {
		t.Setenv(EnvTokenServiceURL, "http://facade-from-env:8080/internal/tokens")

		in := validConfigJSON()
		in["token_service_url"] = "http://facade-from-config:8080/internal/tokens"
		cfg, err := ParseConfig(toJSON(t, in))
		require.NoError(t, err)
		assert.Equal(t, "http://facade-from-config:8080/internal/tokens", cfg.TokenServiceURL)
	})
}

// testPrivacyNoticeID is a well-formed privacy notice UUID for config tests.
const testPrivacyNoticeID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"

// TestParseConfig_ConsentLookupOptions covers check_mode, privacy_notice_id,
// purpose and require_contract.
func TestParseConfig_ConsentLookupOptions(t *testing.T) {
	tests := []struct {
		name      string
		set       map[string]interface{}
		errSubstr string
		check     func(t *testing.T, cfg *Config)
	}{
		{
			name: "check_mode defaults to list",
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, CheckModeList, cfg.CheckMode)
			},
		},
		{
			name: "check_mode list is kept",
			set:  map[string]interface{}{"check_mode": CheckModeList},
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, CheckModeList, cfg.CheckMode)
			},
		},
		{
			name: "check_mode check with privacy_notice_id",
			set:  map[string]interface{}{"check_mode": CheckModeCheck, "privacy_notice_id": testPrivacyNoticeID},
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, CheckModeCheck, cfg.CheckMode)
				assert.Equal(t, testPrivacyNoticeID, cfg.PrivacyNoticeID)
			},
		},
		{
			name: "check_mode check without privacy_notice_id is valid",
			set:  map[string]interface{}{"check_mode": CheckModeCheck},
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, CheckModeCheck, cfg.CheckMode)
				assert.Empty(t, cfg.PrivacyNoticeID)
			},
		},
		{
			name:      "unknown check_mode is rejected",
			set:       map[string]interface{}{"check_mode": "receipt"},
			errSubstr: "check_mode must be",
		},
		{
			name:      "check_mode is case-sensitive",
			set:       map[string]interface{}{"check_mode": "LIST"},
			errSubstr: "check_mode must be",
		},
		{
			name: "uppercase privacy_notice_id is lowercased",
			set:  map[string]interface{}{"privacy_notice_id": strings.ToUpper(testPrivacyNoticeID)},
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, testPrivacyNoticeID, cfg.PrivacyNoticeID)
			},
		},
		{
			name: "removed Visions options still load",
			set:  map[string]interface{}{"consent_api_host": "consent.example", "consent_key": "k"},
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, CheckModeList, cfg.CheckMode)
			},
		},
		{
			name:      "malformed privacy_notice_id is rejected",
			set:       map[string]interface{}{"privacy_notice_id": "notice-1"},
			errSubstr: "privacy_notice_id must be a UUID",
		},
		{
			name: "purpose and require_contract are kept",
			set:  map[string]interface{}{"purpose": "Service improvement", "require_contract": true},
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "Service improvement", cfg.Purpose)
				assert.True(t, cfg.RequireContract)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validConfigJSON()
			for k, v := range tt.set {
				in[k] = v
			}
			cfg, err := ParseConfig(toJSON(t, in))
			if tt.errSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			require.NoError(t, err)
			tt.check(t, cfg)
		})
	}
}

// TestParseConfig_TokenAudienceDefault verifies the audience defaults to the
// consent-manager target and that an explicit value is kept.
func TestParseConfig_TokenAudienceDefault(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		want       string
	}{
		{name: "defaults when omitted", configured: "", want: DefaultTokenAudience},
		{name: "keeps an explicit audience", configured: "some-other-target", want: "some-other-target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validConfigJSON()
			if tc.configured != "" {
				in["token_audience"] = tc.configured
			}
			cfg, err := ParseConfig(toJSON(t, in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.TokenAudience)
		})
	}
}

// TestParseConfig_TokenServiceURLValidation rejects a token service URL that is
// not an http(s) URL - a typo there would otherwise surface as a failed consent
// check on the data path.
func TestParseConfig_TokenServiceURLValidation(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{name: "not a URL", url: "not-a-url"},
		{name: "wrong scheme", url: "ftp://facade:8080/internal/tokens"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validConfigJSON()
			in["token_service_url"] = tc.url
			_, err := ParseConfig(toJSON(t, in))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token_service_url")
		})
	}
}

// TestParseConfig_Audit covers the audit config: enabling requires an endpoint,
// and the endpoint falls back to its env var.
func TestParseConfig_Audit(t *testing.T) {
	t.Run("audit_enabled requires an endpoint", func(t *testing.T) {
		in := validConfigJSON()
		in["audit_enabled"] = true
		_, err := ParseConfig(toJSON(t, in))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit_otlp_endpoint is required")
	})

	t.Run("audit_enabled with an endpoint is valid", func(t *testing.T) {
		in := validConfigJSON()
		in["audit_enabled"] = true
		in["audit_otlp_endpoint"] = "http://otel:4318"
		cfg, err := ParseConfig(toJSON(t, in))
		require.NoError(t, err)
		assert.True(t, cfg.AuditEnabled)
		assert.Equal(t, "http://otel:4318", cfg.AuditOTLPEndpoint)
	})

	t.Run("endpoint falls back to env", func(t *testing.T) {
		t.Setenv(EnvAuditOTLPEndpoint, "http://otel-env:4318")
		in := validConfigJSON()
		in["audit_enabled"] = true
		cfg, err := ParseConfig(toJSON(t, in))
		require.NoError(t, err)
		assert.Equal(t, "http://otel-env:4318", cfg.AuditOTLPEndpoint)
	})
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid config passes validation",
			config: Config{
				CheckMode:               DefaultCheckMode,
				ConsentAPIURL:           "https://consent.example.com",
				ConsentAPITimeout:       DefaultConsentAPITimeout,
				OwnerResolverURL:        "https://owner-resolver.example.com/resolve",
				OwnerResolverTimeout:    DefaultOwnerResolverTimeout,
				ConsentAPIPrefix:        DefaultConsentAPIPrefix,
				ParticipantToken:        "static-token",
				ParticipantTokenTTL:     DefaultParticipantTokenTTL,
				MaxResolveBodyBytes:     DefaultMaxResolveBodyBytes,
				ResponsePhaseTimeout:    DefaultResponsePhaseTimeout,
				MaxOwnersPerResponse:    DefaultMaxOwnersPerResponse,
				JWTHeaderName:           DefaultJWTHeaderName,
				DenyStatusCode:          DefaultDenyStatusCode,
				DenyResponseBody:        DefaultDenyResponseBody,
				DenyResponseContentType: DefaultDenyResponseContentType,
			},
		},
		{
			name: "missing URL fails",
			config: Config{
				ConsentAPITimeout: DefaultConsentAPITimeout,
				DenyStatusCode:    DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "consent_api_url is required",
		},
		{
			name: "missing owner_resolver_url fails",
			config: Config{
				ConsentAPIURL:        "https://consent.example.com",
				ConsentAPITimeout:    DefaultConsentAPITimeout,
				ConsentAPIPrefix:     DefaultConsentAPIPrefix,
				OwnerResolverTimeout: DefaultOwnerResolverTimeout,
				ParticipantTokenTTL:  DefaultParticipantTokenTTL,
				MaxResolveBodyBytes:  DefaultMaxResolveBodyBytes,
				ResponsePhaseTimeout: DefaultResponsePhaseTimeout,
				MaxOwnersPerResponse: DefaultMaxOwnersPerResponse,
				DenyStatusCode:       DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "owner_resolver_url is required",
		},
		{
			name: "an out-of-range max_resolve_body_bytes fails",
			config: Config{
				ConsentAPIURL:        "https://consent.example.com",
				ConsentAPITimeout:    DefaultConsentAPITimeout,
				ConsentAPIPrefix:     DefaultConsentAPIPrefix,
				OwnerResolverURL:     "https://owner-resolver.example.com/resolve",
				OwnerResolverTimeout: DefaultOwnerResolverTimeout,
				ParticipantToken:     "static-token",
				ParticipantTokenTTL:  DefaultParticipantTokenTTL,
				MaxResolveBodyBytes:  MaxMaxResolveBodyBytes + 1,
				ResponsePhaseTimeout: DefaultResponsePhaseTimeout,
				MaxOwnersPerResponse: DefaultMaxOwnersPerResponse,
				DenyStatusCode:       DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "max_resolve_body_bytes must be between",
		},
		{
			name: "an out-of-range participant_token_ttl fails",
			config: Config{
				ConsentAPIURL:        "https://consent.example.com",
				ConsentAPITimeout:    DefaultConsentAPITimeout,
				ConsentAPIPrefix:     DefaultConsentAPIPrefix,
				OwnerResolverURL:     "https://owner-resolver.example.com/resolve",
				OwnerResolverTimeout: DefaultOwnerResolverTimeout,
				ParticipantToken:     "static-token",
				// Large enough that `time.Duration(ttl) * time.Second` overflows
				// into a negative duration, expiring every token immediately.
				ParticipantTokenTTL:  1 << 60,
				MaxResolveBodyBytes:  DefaultMaxResolveBodyBytes,
				ResponsePhaseTimeout: DefaultResponsePhaseTimeout,
				MaxOwnersPerResponse: DefaultMaxOwnersPerResponse,
				DenyStatusCode:       DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "participant_token_ttl must be between",
		},
		{
			name: "no credential source fails",
			config: Config{
				ConsentAPIURL:        "https://consent.example.com",
				ConsentAPITimeout:    DefaultConsentAPITimeout,
				ConsentAPIPrefix:     DefaultConsentAPIPrefix,
				OwnerResolverURL:     "https://owner-resolver.example.com/resolve",
				OwnerResolverTimeout: DefaultOwnerResolverTimeout,
				ParticipantTokenTTL:  DefaultParticipantTokenTTL,
				MaxResolveBodyBytes:  DefaultMaxResolveBodyBytes,
				ResponsePhaseTimeout: DefaultResponsePhaseTimeout,
				MaxOwnersPerResponse: DefaultMaxOwnersPerResponse,
				DenyStatusCode:       DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "one of token_service_url or participant_token is required",
		},
		{
			name: "a consent_api_prefix without a leading slash fails",
			config: Config{
				ConsentAPIURL:        "https://consent.example.com",
				ConsentAPITimeout:    DefaultConsentAPITimeout,
				ConsentAPIPrefix:     "v1",
				OwnerResolverURL:     "https://owner-resolver.example.com/resolve",
				OwnerResolverTimeout: DefaultOwnerResolverTimeout,
				ParticipantToken:     "static-token",
				ParticipantTokenTTL:  DefaultParticipantTokenTTL,
				MaxResolveBodyBytes:  DefaultMaxResolveBodyBytes,
				ResponsePhaseTimeout: DefaultResponsePhaseTimeout,
				MaxOwnersPerResponse: DefaultMaxOwnersPerResponse,
				DenyStatusCode:       DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "consent_api_prefix must start with",
		},
		{
			name: "an out-of-range owner_resolver_timeout fails",
			config: Config{
				ConsentAPIURL:        "https://consent.example.com",
				ConsentAPITimeout:    DefaultConsentAPITimeout,
				ConsentAPIPrefix:     DefaultConsentAPIPrefix,
				OwnerResolverURL:     "https://owner-resolver.example.com/resolve",
				OwnerResolverTimeout: MaxOwnerResolverTimeout + 1,
				ParticipantToken:     "static-token",
				ParticipantTokenTTL:  DefaultParticipantTokenTTL,
				MaxResolveBodyBytes:  DefaultMaxResolveBodyBytes,
				ResponsePhaseTimeout: DefaultResponsePhaseTimeout,
				MaxOwnersPerResponse: DefaultMaxOwnersPerResponse,
				DenyStatusCode:       DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "owner_resolver_timeout must be between",
		},
		{
			name: "negative timeout fails",
			config: Config{
				ConsentAPIURL:     "https://consent.example.com",
				ConsentAPITimeout: -1,
				ConsentAPIPrefix:  DefaultConsentAPIPrefix,
				OwnerResolverURL:  "https://owner-resolver.example.com/resolve",
				DenyStatusCode:    DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "consent_api_timeout must be between",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestConsentFilter_ParseConf_Integration(t *testing.T) {
	// Verify that the plugin's ParseConf method correctly returns a *Config.
	p := &ConsentFilter{}

	t.Run("valid config returns *Config", func(t *testing.T) {
		input := []byte(`{"consent_api_url": "https://consent.example.com/api", "owner_resolver_url": "https://owner-resolver.example.com/resolve", "token_service_url": "https://facade.example.com/internal/tokens"}`)
		conf, err := p.ParseConf(input)
		require.NoError(t, err)

		cfg, ok := conf.(*Config)
		require.True(t, ok, "ParseConf should return *Config")
		assert.Equal(t, "https://consent.example.com/api", cfg.ConsentAPIURL)
		assert.Equal(t, DefaultConsentAPITimeout, cfg.ConsentAPITimeout)
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		input := []byte(`{"consent_api_timeout": 3000}`)
		conf, err := p.ParseConf(input)
		require.Error(t, err)
		assert.Nil(t, conf)
	})

	t.Run("empty input returns error", func(t *testing.T) {
		conf, err := p.ParseConf(nil)
		require.Error(t, err)
		assert.Nil(t, conf)
	})
}

func TestConfig_IsFailOpen(t *testing.T) {
	tests := []struct {
		name     string
		failOpen *bool
		want     bool
	}{
		{name: "nil defaults to false (fail-closed)", failOpen: nil, want: false},
		{name: "explicitly true is fail-open", failOpen: boolPtr(true), want: true},
		{name: "explicitly false is fail-closed", failOpen: boolPtr(false), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{FailOpen: tt.failOpen}
			assert.Equal(t, tt.want, cfg.IsFailOpen())
		})
	}
}

// TestClaimKeysToDecode verifies which claims the request phase decodes: the
// configured forward list plus the root of the consumer-claim path, so the
// consuming participant can still be read in the response phase.
func TestClaimKeysToDecode(t *testing.T) {
	tests := []struct {
		name     string
		forward  []string
		consumer string
		want     []string
	}{
		{
			name: "empty forward list decodes every claim",
			want: nil,
		},
		{
			name:     "the consumer-claim root is added to the forward list",
			forward:  []string{"sub"},
			consumer: "verifiableCredential.issuer",
			want:     []string{"sub", "verifiableCredential"},
		},
		{
			name:     "an already-listed root is not added twice",
			forward:  []string{"sub", "verifiableCredential"},
			consumer: "verifiableCredential.issuer",
			want:     []string{"sub", "verifiableCredential"},
		},
		{
			name:     "a single-segment consumer claim is its own root",
			forward:  []string{"sub"},
			consumer: "issuer",
			want:     []string{"sub", "issuer"},
		},
		{
			name:    "no consumer claim leaves the forward list alone",
			forward: []string{"sub"},
			want:    []string{"sub"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claimKeysToDecode(&Config{JWTClaimsToForward: tt.forward, ConsumerClaim: tt.consumer})
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestParseConfig_PrefixNormalisation verifies a trailing separator is trimmed
// rather than concatenated into a double slash in every endpoint URL.
func TestParseConfig_PrefixNormalisation(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		want       string
	}{
		{name: "defaults when omitted", configured: "", want: DefaultConsentAPIPrefix},
		{name: "keeps a well-formed prefix", configured: "/v2", want: "/v2"},
		{name: "trims a trailing separator", configured: "/v2/", want: "/v2"},
		{name: "a bare separator is left alone", configured: "/", want: "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validConfigJSON()
			if tc.configured != "" {
				in["consent_api_prefix"] = tc.configured
			}
			cfg, err := ParseConfig(toJSON(t, in))
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.ConsentAPIPrefix)
		})
	}
}
