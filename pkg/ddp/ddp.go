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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	LengthMask = uint16(0x03ff)

	HeaderSize    = 5
	ExtHeaderSize = 13
)

type (
	Header struct {
		Size                 uint16
		DstSocket, SrcSocket Socket
		Proto                uint8
	}
	Packet struct {
		Header
		Data []byte
	}

	ExtHeader struct {
		Size, Cksum          uint16
		DstNet, SrcNet       Network
		DstNode, SrcNode     Node
		DstSocket, SrcSocket Socket
		Proto                uint8
	}
	ExtPacket struct {
		ExtHeader
		Data []byte
	}
)

// Unmarshals a packet from bytes.
func Unmarshal(data []byte, pak *Packet) error {
	r := bytes.NewReader(data)

	err := binary.Read(r, binary.BigEndian, &pak.Header)
	if err != nil {
		return fmt.Errorf("read ddp header: %s", err.Error())
	}

	pak.Data = make([]byte, (pak.Size&LengthMask)-HeaderSize)
	n, err := r.Read(pak.Data)
	if err != nil {
		return fmt.Errorf("read ddp: %s", err.Error())
	} else if n < len(pak.Data) {
		return fmt.Errorf("read ddp: incomplete data (%d < %d)", n, len(pak.Data))
	}

	_, err = r.ReadByte()
	if err != io.EOF {
		return fmt.Errorf("read ddp: excess data")
	}

	return nil
}

// Marshals a packet to bytes.
func Marshal(pak Packet) ([]byte, error) {
	w := bytes.NewBuffer([]byte{})
	err := binary.Write(w, binary.BigEndian, pak.Header)
	if err != nil {
		return nil, fmt.Errorf("write ddp: %s", err.Error())
	}

	n, err := w.Write(pak.Data)
	if err != nil {
		return nil, fmt.Errorf("write data: %s", err.Error())
	} else if n < len(pak.Data) {
		return nil, fmt.Errorf("write data: incomplete data (%d < %d)", n, len(pak.Data))
	}

	return w.Bytes(), nil
}

// Unmarshals a packet from bytes.
func ExtUnmarshal(data []byte, pak *ExtPacket) error {
	r := bytes.NewReader(data)

	err := binary.Read(r, binary.BigEndian, &pak.ExtHeader)
	if err != nil {
		return fmt.Errorf("read ddp header: %s", err.Error())
	}

	pak.Data = make([]byte, (pak.Size&LengthMask)-ExtHeaderSize)
	n, err := r.Read(pak.Data)
	if err != nil {
		return fmt.Errorf("read ddp: %s", err.Error())
	} else if n < len(pak.Data) {
		return fmt.Errorf("read ddp: incomplete data (%d < %d)", n, len(pak.Data))
	}

	_, err = r.ReadByte()
	if err != io.EOF {
		return fmt.Errorf("read ddp: excess data")
	}

	return nil
}

// Marshals a packet to bytes.
func ExtMarshal(pak ExtPacket) ([]byte, error) {
	w := bytes.NewBuffer([]byte{})
	err := binary.Write(w, binary.BigEndian, pak.ExtHeader)
	if err != nil {
		return nil, fmt.Errorf("write ddp: %s", err.Error())
	}

	n, err := w.Write(pak.Data)
	if err != nil {
		return nil, fmt.Errorf("write data: %s", err.Error())
	} else if n < len(pak.Data) {
		return nil, fmt.Errorf("write data: incomplete data (%d < %d)", n, len(pak.Data))
	}

	return w.Bytes(), nil
}

func ExtToShort(ext ExtPacket) Packet {
	return Packet{
		Header: Header{
			Size:      ext.Size - ExtHeaderSize + HeaderSize,
			DstSocket: ext.DstSocket,
			SrcSocket: ext.SrcSocket,
			Proto:     ext.Proto,
		},
		Data: ext.Data,
	}
}

func ShortToExt(pak Packet, network Network, dstNode, srcNode Node) ExtPacket {
	return ExtPacket{
		ExtHeader: ExtHeader{
			Size:      pak.Size - HeaderSize + ExtHeaderSize,
			DstNet:    network,
			DstNode:   dstNode,
			DstSocket: pak.DstSocket,
			SrcNet:    network,
			SrcNode:   srcNode,
			SrcSocket: pak.SrcSocket,
			Proto:     pak.Proto,
		},
		Data: pak.Data,
	}
}
