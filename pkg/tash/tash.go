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

// Package tash handles encoding and decoding communication with a TashTalk microprocessor
// over a serial connection.
//
// See https://github.com/lampmerchant/tashtalk/blob/main/documentation/protocol.md
package tash

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/llap"
	"github.com/sfiera/multitalk/pkg/localtalk"
)

const (
	escapeHeader       = byte(0x00)
	escapeZero         = byte(0xff)
	escapeFrameDone    = byte(0xfd)
	escapeFramingError = byte(0xfe)
	escapeFrameAbort   = byte(0xfa)

	commandNoop    = byte(0x00)
	commandFrame   = byte(0x01)
	commandNodeIDs = byte(0x02)
)

// A Decoder translates TashTalk serial input to LLAP packets.
type Decoder struct {
	r io.ByteReader
}

// NewDecoder returns a Decoder with r as its input.
func NewDecoder(r io.Reader) Decoder {
	if br, ok := r.(io.ByteReader); ok {
		return Decoder{r: br}
	} else {
		return Decoder{r: bufio.NewReader(r)}
	}
}

// Decode decodes the next valid packet from the decoder’s input.
// If necessary, it blocks until a full packet can be decoded.
//
// Returns an error if an error condition occurs reading from the input
// (including EOF).
//
// If an error occurs decoding a packet, then the packet is silently dropped
// and decoding continues. Such error cases include:
// * Malformed packet
// * Invalid CRC16
// * Frame error from TashTalk
// * Frame aborted from TashTalk
func (d *Decoder) Decode(pak *llap.Packet) (err error) {
	escape := false
	buf := bytes.Buffer{}

	for {
		c, err := d.r.ReadByte()
		if err != nil {
			return err
		}

		if !escape {
			if c == escapeHeader {
				escape = true
			} else {
				buf.WriteByte(c)
			}
			continue
		}

		escape = false
		if c != escapeFrameDone {
			if c == escapeZero {
				buf.WriteByte(0x00)
			} else {
				buf.Reset()
			}
			continue
		}

		data := buf.Bytes()
		if localtalk.SumCRC(data) != localtalk.ValidCRC {
			buf.Reset()
			continue
		}

		err = llap.Unmarshal(data[:len(data)-2], pak)
		if err != nil {
			buf.Reset()
			continue
		}
		return nil
	}
}

// An Encoder translates LLAP packets to TashTalk serial output.
type Encoder struct {
	w     io.Writer
	ready bool
}

// NewEncoder returns a Decoder with w as its output.
func NewEncoder(w io.Writer) Encoder {
	return Encoder{w: w}
}

// Reset sends a stream of 1024 no-op bytes.
// This resets TashTalk and ensures that it is in a state where
// it is ready to accept further commands.
func (e *Encoder) Reset() error {
	data := [1024]byte{}
	_, err := e.w.Write(data[:])
	if err != nil {
		e.ready = false
		return err
	}
	e.ready = true
	return nil
}

// Encode encodes the packet and sends it to the decoder’s output.
// If necessary, it blocks until the full packet can be sent.
// The packet is CRCed and preceded by a TashTalk frame command.
//
// If the output is not in a ready state (either because the encoder
// was just created, or because a previous write operation failed),
// then it first calls Reset() to return to a known-good state.
//
// If an error occurs while encoding the packet, the packet is not
// sent, but the stream is assumed to remain valid.
func (e *Encoder) Encode(pak llap.Packet) error {
	if !e.ready {
		err := e.Reset()
		if err != nil {
			return err
		}
	}

	switch pak.Kind {
	case llap.TypeDDP:
		if len(pak.Payload) < 2 {
			return fmt.Errorf("invalid DDP packet length: %d", len(pak.Payload))
		}
		inferredLength := binary.BigEndian.Uint16(pak.Payload[:2]) & 0x03ff
		if int(inferredLength) != len(pak.Payload) {
			return fmt.Errorf("DDP packet length mismatch: %d vs. %d", len(pak.Payload), inferredLength)
		}
	case llap.TypeEnq, llap.TypeAck:
		if len(pak.Payload) != 0 {
			return fmt.Errorf("control frame packet with payload")
		}
	default:
		return fmt.Errorf("invalid packet type: $%02x", pak.Kind)
	}

	marshaled, err := llap.Marshal(pak)
	if err != nil {
		return err
	}
	fcs := localtalk.SumCRC(marshaled)
	data := []byte{commandFrame}
	data = append(data, marshaled...)
	data = append(data, byte(fcs), byte(fcs>>8))
	_, err = e.w.Write(data)
	if err != nil {
		e.ready = false
		return err
	}
	return nil
}

// SetNodeIDs sets the node IDs that TashTalk will respond to ENQ and RTS frames for.
func (e *Encoder) SetNodeIDs(ids NodeSet) error {
	if !e.ready {
		err := e.Reset()
		if err != nil {
			return err
		}
	}

	data := []byte{commandNodeIDs}
	data = append(data, ids[:]...)
	_, err := e.w.Write(data)
	if err != nil {
		e.ready = false
		return err
	}
	return nil
}

// A NodeSet represents a mask of 256 nodes within a network.
//
// Each bit specifies a node ID, starting from the LSB of bitfield[0],
// and ending with the MSB of bitfield[31].
// Node IDs 0 and 255 have special meaning and should not be set.
type NodeSet [32]byte

// NewNodeSet returns a NodeSet containing the specified nodes.
func NewNodeSet(nodes ...ddp.Node) NodeSet {
	ns := NodeSet{}
	for _, n := range nodes {
		ns.Add(n)
	}
	return ns
}

// IsSet returns true if the given node is a member of the NodeSet.
func (ns NodeSet) IsSet(n ddp.Node) bool {
	return (ns[n>>3] & (1 << (n & 0x7))) != 0
}

// Add adds a node to the NodeSet.
func (ns *NodeSet) Add(n ddp.Node) {
	ns[n>>3] |= (1 << (n & 0x7))
}

// Remove removes a node from the NodeSet.
func (ns *NodeSet) Remove(n ddp.Node) {
	ns[n>>3] &= ^uint8(1 << (n & 0x7))
}
