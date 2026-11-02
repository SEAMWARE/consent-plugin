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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUUID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "lowercase v4", in: "3fa85f64-5717-4562-b3fc-2c963f66afa6", want: true},
		{name: "uppercase", in: "3FA85F64-5717-4562-B3FC-2C963F66AFA6", want: true},
		{name: "nil uuid", in: "00000000-0000-0000-0000-000000000000", want: true},
		{name: "empty", in: "", want: false},
		{name: "no hyphens", in: "3fa85f6457174562b3fc2c963f66afa6", want: false},
		{name: "braced", in: "{3fa85f64-5717-4562-b3fc-2c963f66afa6}", want: false},
		{name: "non-hex digit", in: "3fa85f64-5717-4562-b3fc-2c963f66afag", want: false},
		{name: "too short", in: "3fa85f64-5717-4562-b3fc-2c963f66afa", want: false},
		{name: "trailing newline", in: "3fa85f64-5717-4562-b3fc-2c963f66afa6\n", want: false},
		{name: "path traversal", in: "../../participants/me", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsUUID(tt.in))
		})
	}
}
