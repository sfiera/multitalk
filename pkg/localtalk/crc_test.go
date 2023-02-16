// Copyright (c) 2009-2023 Rob Braun <bbraun@synack.net> and others
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of Rob Braun nor the names of his contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package localtalk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSizes(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		want  uint16
	}{{
		name:  "empty",
		input: "",
		want:  0x0000,
	}, {
		name:  "zero",
		input: "\x00",
		want:  0xf078,
	}, {
		name:  "string",
		input: "LocalTalk",
		want:  0xc5a1,
	}, {
		name:  "trailing_fcs",
		input: "LocalTalk\xa1\xc5",
		want:  0x0f47,
		// Strings ended with a correct FCS should always yield 0x0f47.
	}} {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			sum := SumCRC([]byte(tt.input))
			assert.Equal(tt.want, sum)
		})
	}
}
