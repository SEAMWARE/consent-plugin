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

package ownerresolver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testConsumer is the consuming participant forwarded for CONTRACT lookup only.
const testConsumer = "did:web:fancy-marketplace.biz"

func TestResolve_SendsBodyAndParsesClaims(t *testing.T) {
	var gotPath string
	var gotReq resolveRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotReq)
		// the resolver must not receive any caller identity
		if strings.Contains(string(raw), "authorization") || strings.Contains(string(raw), "Authorization") {
			t.Errorf("resolve request leaked a caller identity: %s", raw)
		}
		_, _ = w.Write([]byte(`{"consentRequired":true,"scheme":"identifier","claims":[{"selector":{"type":"json-pointer","value":""},"ownerId":"alice-42","dataResource":"urn:ngsi-ld:PersonalProfile:alice"}]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+resolvePath, 0)
	res, err := c.Resolve(context.Background(), Resource{
		Service: "mp-data-service", Method: "GET",
		Path: "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice", ContentType: "application/ld+json",
	}, Parties{Consumer: testConsumer}, []byte(`{"id":"urn:ngsi-ld:PersonalProfile:alice","dataOwner":"alice-42"}`))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotPath != resolvePath {
		t.Fatalf("posted to %q", gotPath)
	}
	if gotReq.Body == nil || gotReq.Body.Encoding != encodingJSON {
		t.Fatalf("expected json body, got %+v", gotReq.Body)
	}
	if gotReq.Resource.Service != "mp-data-service" || gotReq.Resource.Path == "" {
		t.Fatalf("resource not forwarded: %+v", gotReq.Resource)
	}
	if gotReq.Parties == nil || gotReq.Parties.Consumer != testConsumer {
		t.Fatalf("consumer not forwarded for contract lookup: %+v", gotReq.Parties)
	}
	if !res.ConsentRequired || len(res.Claims) != 1 ||
		res.Claims[0].OwnerID != "alice-42" ||
		res.Claims[0].DataResource != "urn:ngsi-ld:PersonalProfile:alice" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// TestResolve_DecodesClaimScope verifies the optional purpose, contract and
// notice fields reach the plugin, and are empty when the resolver omits them.
func TestResolve_DecodesClaimScope(t *testing.T) {
	tests := []struct {
		name  string
		claim string
		want  Claim
	}{
		{
			name:  "all scope fields",
			claim: `{"ownerId":"alice-42","purpose":"Trip planning","contractUri":"https://contracts.example/c1","privacyNoticeId":"3f1e2d4c-5b6a-4789-8abc-def012345678"}`,
			want: Claim{
				OwnerID: "alice-42", Purpose: "Trip planning",
				ContractURI: "https://contracts.example/c1", PrivacyNoticeID: "3f1e2d4c-5b6a-4789-8abc-def012345678",
			},
		},
		{
			name:  "no scope fields",
			claim: `{"ownerId":"alice-42"}`,
			want:  Claim{OwnerID: "alice-42"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"consentRequired":true,"claims":[` + tt.claim + `]}`))
			}))
			defer srv.Close()

			res, err := NewClient(srv.URL+resolvePath, 0).Resolve(context.Background(), Resource{}, Parties{}, nil)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(res.Claims) != 1 || res.Claims[0] != tt.want {
				t.Fatalf("got %+v, want %+v", res.Claims, tt.want)
			}
		})
	}
}

func TestResolve_NoBodyUsesEncodingNone(t *testing.T) {
	var gotReq resolveRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotReq)
		_, _ = w.Write([]byte(`{"consentRequired":true,"claims":[{"selector":{"type":"whole"},"ownerId":"bob-7"}]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+resolvePath, 0)
	res, err := c.Resolve(context.Background(), Resource{Service: "file-service", Path: "/files/bob-7/x.pdf"}, Parties{}, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotReq.Body == nil || gotReq.Body.Encoding != encodingNone {
		t.Fatalf("expected encoding none, got %+v", gotReq.Body)
	}
	if gotReq.Parties != nil {
		t.Fatalf("no consumer given => parties must be omitted, got %+v", gotReq.Parties)
	}
	if len(res.Claims) != 1 || res.Claims[0].OwnerID != "bob-7" || res.Claims[0].DataResource != "" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestResolve_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"cannot resolve owner"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+resolvePath, 0)
	if _, err := c.Resolve(context.Background(), Resource{Path: "/x"}, Parties{}, nil); err == nil {
		t.Fatal("expected error on non-2xx resolver response")
	}
}

// TestDescribeBody verifies the three body encodings stay distinguishable.
//
// A payload the plugin cannot parse used to be described exactly like no payload
// at all, so the resolver judged ownership from the resource descriptor alone
// and a malformed-but-personal response (a truncated write, a content-type
// mismatch, an upstream answering XML on a route declared JSON) was released
// without ever being inspected.
func TestDescribeBody(t *testing.T) {
	tests := []struct {
		name            string
		payload         []byte
		contentType     string
		wantEncoding    string
		wantContent     string
		wantContentType string
		wantSize        int
	}{
		{
			name:         "no payload",
			payload:      nil,
			wantEncoding: encodingNone,
		},
		{
			name:         "empty payload is no payload",
			payload:      []byte{},
			wantEncoding: encodingNone,
		},
		{
			name:         "valid JSON is carried verbatim",
			payload:      []byte(`{"id":"urn:entity:1"}`),
			contentType:  "application/json",
			wantEncoding: encodingJSON,
			wantContent:  `{"id":"urn:entity:1"}`,
		},
		{
			name:            "unparseable payload is opaque, not absent",
			payload:         []byte("<person><email>alice@example.org</email></person>"),
			contentType:     "application/xml",
			wantEncoding:    encodingOpaque,
			wantContentType: "application/xml",
			wantSize:        49,
		},
		{
			name:            "truncated JSON is opaque, not absent",
			payload:         []byte(`{"id":"urn:entity`),
			contentType:     "application/json",
			wantEncoding:    encodingOpaque,
			wantContentType: "application/json",
			wantSize:        17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := describeBody(tt.payload, tt.contentType)
			if got.Encoding != tt.wantEncoding {
				t.Fatalf("encoding = %q, want %q", got.Encoding, tt.wantEncoding)
			}
			if string(got.Content) != tt.wantContent {
				t.Errorf("content = %q, want %q", string(got.Content), tt.wantContent)
			}
			if got.ContentType != tt.wantContentType {
				t.Errorf("contentType = %q, want %q", got.ContentType, tt.wantContentType)
			}
			if got.Size != tt.wantSize {
				t.Errorf("size = %d, want %d", got.Size, tt.wantSize)
			}
		})
	}
}

// TestResolve_SendsOpaqueBodyForUnparseablePayload verifies the distinction
// survives onto the wire, so the resolver can act on it.
func TestResolve_SendsOpaqueBodyForUnparseablePayload(t *testing.T) {
	var gotReq resolveRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotReq)
		w.Header().Set("Content-Type", contentTypeJSON)
		_, _ = w.Write([]byte(`{"consentRequired":true,"claims":[{"ownerId":"did:key:zOwner"}]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, DefaultTimeoutMs)
	_, err := c.Resolve(context.Background(),
		Resource{Service: "svc", Method: "GET", Path: "/p", ContentType: "application/xml"},
		Parties{Consumer: testConsumer},
		[]byte("<person/>"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if gotReq.Body == nil {
		t.Fatal("no body descriptor was sent")
	}
	if gotReq.Body.Encoding != encodingOpaque {
		t.Errorf("encoding = %q, want %q — an unreadable payload must not look like no payload",
			gotReq.Body.Encoding, encodingOpaque)
	}
	if gotReq.Body.ContentType != "application/xml" {
		t.Errorf("contentType = %q, want application/xml", gotReq.Body.ContentType)
	}
	if len(gotReq.Body.Content) != 0 {
		t.Errorf("an opaque body must not carry content, got %q", string(gotReq.Body.Content))
	}
}
