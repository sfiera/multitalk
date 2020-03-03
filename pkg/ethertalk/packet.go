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
package ethertalk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethernet"
)

var (
	SNAP           = LinkHeader{0xAA, 0xAA, 0x03}
	AppleTalkProto = SNAPProto{[3]byte{0x08, 0x00, 0x07}, 0x809B}
	AARPProto      = SNAPProto{[3]byte{0x00, 0x00, 0x00}, 0x80F3}

	AppleTalkBroadcast = ethernet.Addr{0x09, 0x00, 0x07, 0xff, 0xff, 0xff}
)

const (
	EthHeaderSize  = 13
	LinkHeaderSize = 3
	SNAPProtoSize  = 5
)

type (
	EthHeader struct {
		Dst, Src ethernet.Addr
		Size     uint16
	}
	LinkHeader struct {
		DSAP, SSAP byte
		Control    byte
	}
	SNAPProto struct {
		OUI   [3]byte
		Proto uint16
	}
	Packet struct {
		EthHeader
		LinkHeader
		SNAPProto
		Data []byte
		Pad  []byte
	}
)

// Unmarshals a packet from bytes.
func Unmarshal(data []byte, pak *Packet) error {
	r := bytes.NewReader(data)

	err := binary.Read(r, binary.BigEndian, &pak.EthHeader)
	if err != nil {
		return fmt.Errorf("read eth header: %s", err.Error())
	}

	err = binary.Read(r, binary.BigEndian, &pak.LinkHeader)
	if err != nil {
		return fmt.Errorf("read link header: %s", err.Error())
	} else if pak.LinkHeader != SNAP {
		return fmt.Errorf("read link header: not SNAP")
	}

	err = binary.Read(r, binary.BigEndian, &pak.SNAPProto)
	if err != nil {
		return fmt.Errorf("read snap proto: %s", err.Error())
	}

	pak.Data = make([]byte, pak.Size-LinkHeaderSize+SNAPProtoSize)
	n, err := r.Read(pak.Data)
	if err != nil {
		return fmt.Errorf("read data: %s", err.Error())
	} else if n < len(pak.Data) {
		return fmt.Errorf("read data: incomplete data (%d < %d)", n, len(pak.Data))
	}

	pak.Pad, err = ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read padding: %s", err.Error())
	}

	return nil
}

// Marshals a packet to bytes.
func Marshal(pak Packet) ([]byte, error) {
	w := bytes.NewBuffer([]byte{})
	err := binary.Write(w, binary.BigEndian, pak.EthHeader)
	if err != nil {
		return nil, fmt.Errorf("write eth header: %s", err.Error())
	}

	err = binary.Write(w, binary.BigEndian, pak.LinkHeader)
	if err != nil {
		return nil, fmt.Errorf("write link header: %s", err.Error())
	}

	err = binary.Write(w, binary.BigEndian, pak.SNAPProto)
	if err != nil {
		return nil, fmt.Errorf("write snap proto: %s", err.Error())
	}

	n, err := w.Write(pak.Data)
	if err != nil {
		return nil, fmt.Errorf("write data: %s", err.Error())
	} else if n < len(pak.Data) {
		return nil, fmt.Errorf("write data: incomplete data (%d < %d)", n, len(pak.Data))
	}

	n, err = w.Write(pak.Pad)
	if err != nil {
		return nil, fmt.Errorf("write padding: %s", err.Error())
	} else if n < len(pak.Pad) {
		return nil, fmt.Errorf("write padding: incomplete data (%d < %d)", n, len(pak.Pad))
	}

	return w.Bytes(), nil
}

// Returns true if two packets are equal. Ignores padding.
func Equal(a, b *Packet) bool {
	return ((a.EthHeader == b.EthHeader) &&
		(a.LinkHeader == b.LinkHeader) &&
		(a.SNAPProto == b.SNAPProto) &&
		(bytes.Compare(a.Data, b.Data) == 0))
}

func AppleTalk(src ethernet.Addr, inner ddp.ExtPacket) (*Packet, error) {
	data, err := ddp.ExtMarshal(inner)
	if err != nil {
		return nil, fmt.Errorf("marshal ddp: %s", err.Error())
	}
	return &Packet{
		EthHeader: EthHeader{
			Dst:  AppleTalkBroadcast,
			Src:  src,
			Size: LinkHeaderSize + SNAPProtoSize + uint16(len(data)),
		},
		LinkHeader: SNAP,
		SNAPProto:  AppleTalkProto,
		Data:       data,
	}, nil
}

func AARP(src ethernet.Addr, inner aarp.Packet) (*Packet, error) {
	data, err := aarp.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("marshal aarp: %s", err.Error())
	}
	return &Packet{
		EthHeader: EthHeader{
			Dst:  AppleTalkBroadcast,
			Src:  src,
			Size: LinkHeaderSize + SNAPProtoSize + uint16(len(data)),
		},
		LinkHeader: SNAP,
		SNAPProto:  AARPProto,
		Data:       data,
	}, nil
}
