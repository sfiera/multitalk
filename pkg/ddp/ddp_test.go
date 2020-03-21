// Copyright (c) 2009-2020 Rob Braun <bbraun@synack.net> and others
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

package ddp

import (
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSizes(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(binary.Size(Header{}), headerSize)
	assert.Equal(binary.Size(ExtHeader{}), extHeaderSize)
}

func TestExtUnmarshalNoError(t *testing.T) {
	cases := []struct {
		name, hex string
		expected  ExtPacket
	}{{
		"ZIP",
		"00150000" + // Size and checksum
			"0000ff00ff5f0606" + // 65280.95:6 to 0.255:6
			"06" + // ZIP
			"050000000000012a", // ZIP payload
		ExtPacket{
			ExtHeader{
				Size:      21,
				DstNet:    0,
				SrcNet:    65280,
				DstNode:   255,
				SrcNode:   95,
				DstSocket: 6,
				SrcSocket: 6,
				Proto:     6,
			},
			unhex("050000000000012a"),
		},
	}, {
		"NBP",
		"00260000" + // Size and checksum
			"0000ff00ff5f02fd" + // 65280.95:253 to 0.255:2
			"02" + // NBP
			"2101ff005ffd00034661620b576f726b73746174696f6e012a", // NBP payload
		ExtPacket{
			ExtHeader{
				Size:      38,
				DstNet:    0,
				SrcNet:    65280,
				DstNode:   255,
				SrcNode:   95,
				DstSocket: 2,
				SrcSocket: 253,
				Proto:     2,
			},
			unhex("2101ff005ffd00034661620b576f726b73746174696f6e012a"),
		},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert := assert.New(t)
			p := ExtPacket{}
			if assert.NoError(ExtUnmarshal(unhex(c.hex), &p)) {
				assert.Equal(c.expected, p)
			}
		})
	}
}

func TestError(t *testing.T) {

	cases := []struct {
		name, hex, err string
	}{{
		"empty",
		"",
		"read ddp header: EOF",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert := assert.New(t)
			p := ExtPacket{}
			err := ExtUnmarshal(unhex(c.hex), &p)
			if assert.Error(err) {
				assert.Equal(c.err, err.Error())
			}
		})
	}
}

func unhex(s string) []byte {
	data := []byte{}
	for i := 0; i < len(s); i += 2 {
		n, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			panic(err)
		}
		data = append(data, byte(n))
	}
	return data
}
