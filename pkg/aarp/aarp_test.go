//
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
//
package aarp

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sfiera/multitalk/pkg/ethernet"
)

func TestUnmarshalNoError(t *testing.T) {
	cases := []struct {
		name, hex string
		expected  Packet
	}{{
		"AARP",
		"0001809b0604" + // Ethernet-LLAP bridging
			"0003" + // Probe
			"080007b4b1ce" + "00ff005f" + // This is (tentatively) my address
			"000000000000" + "00ff005f", // Anyone out there using that address?
		Packet{
			EthernetLLAPBridging,
			Body{
				Opcode: ProbeOp,
				Src: AddrPair{
					ethernet.Addr{0x08, 0x00, 0x07, 0xb4, 0xb1, 0xce},
					AtalkAddr{0, 65280, 95},
				},
				Dst: AddrPair{
					ethernet.Addr{},
					AtalkAddr{0, 65280, 95},
				},
			},
		},
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert := assert.New(t)
			p := Packet{}
			if assert.NoError(Unmarshal(unhex(c.hex), &p)) {
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
		"read aarp header: EOF",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert := assert.New(t)
			p := Packet{}
			err := Unmarshal(unhex(c.hex), &p)
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
