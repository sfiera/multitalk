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

// Encodes and decodes AARP (AppleTalk Address Resolution Protocol) packets.
package aarp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethernet"
)

const (
	HardwareEthernet  = Hardware(0x0001)
	ProtoLLAPBridging = Proto(0x809b)
)

var EthernetLLAPBridging = Header{
	Hardware:     HardwareEthernet,
	Proto:        ProtoLLAPBridging,
	HardwareSize: 6,
	ProtoSize:    4,
}

type Opcode uint16

const (
	RequestOp  = Opcode(0x01)
	ResponseOp = Opcode(0x02)
	ProbeOp    = Opcode(0x03)
)

type (
	Hardware uint16
	Proto    uint16
	Header   struct {
		Hardware                Hardware
		Proto                   Proto
		HardwareSize, ProtoSize uint8
	}

	AddrPair struct {
		Hardware ethernet.Addr
		_        uint8
		Proto    ddp.Addr
	}

	Body struct {
		Opcode Opcode
		Src    AddrPair
		Dst    AddrPair
	}

	Packet struct {
		Header
		Body
	}
)

// Unmarshals a packet from bytes.
func Unmarshal(data []byte, pak *Packet) error {
	r := bytes.NewReader(data)

	err := binary.Read(r, binary.BigEndian, &pak.Header)
	if err != nil {
		return fmt.Errorf("read aarp header: %s", err.Error())
	} else if pak.Header != EthernetLLAPBridging {
		return fmt.Errorf("read aarp header: not eth-llap bridging")
	}

	err = binary.Read(r, binary.BigEndian, &pak.Body)
	if err != nil {
		return fmt.Errorf("read aarp body: %s", err.Error())
	}

	_, err = r.ReadByte()
	if err != io.EOF {
		return fmt.Errorf("read aarp: excess data")
	}

	return nil
}

// Marshals a packet to bytes.
func Marshal(pak Packet) ([]byte, error) {
	w := bytes.NewBuffer([]byte{})
	err := binary.Write(w, binary.BigEndian, pak)
	if err != nil {
		return nil, fmt.Errorf("write aarp: %s", err.Error())
	}

	return w.Bytes(), nil
}

// AARP packet for resolving `query` to a hardware address, from `src`.
func Request(src AddrPair, query ddp.Addr) Packet {
	return Packet{
		Header: EthernetLLAPBridging,
		Body: Body{
			Opcode: RequestOp,
			Src:    src,
			Dst:    AddrPair{Proto: query},
		},
	}
}

// AARP packet responding to a request or probe `dst` from `src`.
func Response(src, dst AddrPair) Packet {
	return Packet{
		Header: EthernetLLAPBridging,
		Body: Body{
			Opcode: ResponseOp,
			Src:    src,
			Dst:    dst,
		},
	}
}

// AARP packet for checking that `query` is available, from `src`.
func Probe(src ethernet.Addr, query ddp.Addr) Packet {
	return Packet{
		Header: EthernetLLAPBridging,
		Body: Body{
			Opcode: ProbeOp,
			Src: AddrPair{
				Hardware: src,
				Proto:    query,
			},
			Dst: AddrPair{Proto: query},
		},
	}
}
