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

package consent

// ResetCaches drops every package-wide cache: the participant credentials
// (token, provider self-description and identifier) and the DID ->
// self-description mappings. Consent answers are never cached.
//
// It exists for tests. They currently pass only because httptest allocates a
// fresh base URL per server, which happens to produce a fresh cache key; a test
// that reuses a URL, or one that runs in parallel with another, would otherwise
// see another test's token and fail in an order-dependent way. Production code
// must not call this: dropping a live token mid-flight only causes a re-fetch,
// but there is no reason to.
func ResetCaches() {
	credCacheMu.Lock()
	credCache = map[string]*cacheEntry{}
	credCacheMu.Unlock()

	participantSDMu.Lock()
	participantSDCache = map[string]participantSDEntry{}
	participantSDMu.Unlock()
}
