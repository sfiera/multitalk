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

// Logs received packets
package dbg

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethernet"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

func TestUnmarshalNoError(t *testing.T) {
}

func TestOmissions(t *testing.T) {
	assert := assert.New(t)
	core, output := observer.New(zapcore.InfoLevel)
	log := zap.New(core)

	ctx, cancel := context.WithCancel(context.Background())
	send, recv := Logger(log).Start(ctx)
	send <- ethertalk.Packet{SNAPProto: ethertalk.SNAPProto{OUI: [3]byte{'?', '?', '?'}}}
	close(send)
	cancel()
	<-recv
	assert.Empty([]observer.LoggedEntry{}, output.AllUntimed())
}

func TestMessages(t *testing.T) {
	for _, c := range []struct {
		name   string
		packet ethertalk.Packet
		entry  observer.LoggedEntry
	}{{
		"aarp_eof",
		ethertalk.Packet{SNAPProto: ethertalk.AARPProto},
		msg(zapcore.ErrorLevel, "unmarshal failed",
			zap.String("protocol", "aarp"),
			zap.Error(errors.New("read aarp header: EOF")),
		),
	}, {
		"ddp_eof",
		ethertalk.Packet{SNAPProto: ethertalk.AppleTalkProto},
		msg(zapcore.ErrorLevel, "unmarshal failed",
			zap.String("protocol", "ddp"),
			zap.Error(errors.New("read ddp header: EOF")),
		),
	}, {
		"aarp_probe",
		mustAARP(
			ethernet.Addr{0x08, 0x00, 0x07, 0xb4, 0xb1, 0xce},
			aarp.Packet{
				Header: aarp.EthernetLLAPBridging,
				Body: aarp.Body{
					Dst:    aarp.AddrPair{Proto: ddp.Addr{Network: 1, Node: 2}},
					Src:    aarp.AddrPair{Proto: ddp.Addr{Network: 3, Node: 4}},
					Opcode: aarp.ProbeOp,
				},
			},
		),
		msg(zapcore.InfoLevel, "packet",
			zap.String("protocol", "aarp"),
			zap.String("dst", "1.2"),
			zap.String("src", "3.4"),
			zap.String("op", "probe"),
		),
	}, {
		"ddp_message",
		mustAppleTalk(
			ethernet.Addr{0x08, 0x00, 0x07, 0xb4, 0xb1, 0xce},
			ddp.ExtPacket{
				ExtHeader: ddp.ExtHeader{
					Size:   17,
					DstNet: 0, DstNode: 255, DstSocket: 6,
					SrcNet: 65280, SrcNode: 95, SrcSocket: 6,
					Proto: 1,
				},
				Data: []byte{1, 2, 3, 4},
			},
		),
		msg(zapcore.InfoLevel, "packet",
			zap.String("protocol", "ddp"),
			zap.String("dst", "0.255.6"),
			zap.String("src", "65280.95.6"),
			zap.Uint8("proto", 1),
			zap.Uint16("cksum", 0),
			zap.String("data", "01020304"),
		),
	}} {
		t.Run(c.name, func(t *testing.T) {
			assert := assert.New(t)
			core, output := observer.New(zapcore.InfoLevel)
			log := zap.New(core)

			ctx, cancel := context.WithCancel(context.Background())
			send, recv := Logger(log).Start(ctx)
			send <- c.packet
			close(send)
			cancel()
			<-recv
			assert.Equal([]observer.LoggedEntry{c.entry}, output.AllUntimed())
		})
	}
}

func msg(level zapcore.Level, message string, fields ...zapcore.Field) observer.LoggedEntry {
	return observer.LoggedEntry{
		Entry:   zapcore.Entry{Level: level, Message: message},
		Context: fields,
	}
}

func mustAARP(src ethernet.Addr, pak aarp.Packet) ethertalk.Packet {
	result, err := ethertalk.AARP(src, pak)
	if err != nil {
		panic(err)
	}
	return *result
}

func mustAppleTalk(src ethernet.Addr, pak ddp.ExtPacket) ethertalk.Packet {
	result, err := ethertalk.AppleTalk(src, pak)
	if err != nil {
		panic(err)
	}
	return *result
}
