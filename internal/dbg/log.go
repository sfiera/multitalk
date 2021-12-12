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
	"bytes"
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

type bridge struct {
	log *zap.Logger
}

func Logger(log *zap.Logger) *bridge {
	return &bridge{log}
}

func (b bridge) Start(ctx context.Context) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
) {
	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)
	go b.capture(ctx, recvCh)
	go b.transmit(ctx, sendCh)
	return sendCh, recvCh
}

func (b bridge) transmit(ctx context.Context, sendCh <-chan ethertalk.Packet) {
	for packet := range sendCh {
		switch packet.SNAPProto {
		case ethertalk.AARPProto:
			b.logAARPPacket(packet)
		case ethertalk.AppleTalkProto:
			b.logAppleTalkPacket(packet)
		}
	}
}

func (b bridge) capture(ctx context.Context, recvCh chan<- ethertalk.Packet) {
	<-ctx.Done()
	close(recvCh)
}

func (b bridge) logAARPPacket(packet ethertalk.Packet) {
	log := b.log.With(zap.String("protocol", "aarp"))
	a := aarp.Packet{}
	err := aarp.Unmarshal(packet.Payload, &a)
	if err != nil {
		log.With(zap.Error(err)).Error("unmarshal failed")
		return
	} else if a.Header != aarp.EthernetLLAPBridging {
		log.Warn("not eth-llap bridging")
		return
	}
	log = log.With(
		zap.String("dst", fmt.Sprintf("%d.%d", a.Dst.Proto.Network, a.Dst.Proto.Node)),
		zap.String("src", fmt.Sprintf("%d.%d", a.Src.Proto.Network, a.Src.Proto.Node)),
	)

	switch a.Opcode {
	case aarp.RequestOp:
		log.With(zap.String("op", "request")).Info("packet")
	case aarp.ResponseOp:
		log.With(zap.String("op", "response")).Info("packet")
	case aarp.ProbeOp:
		log.With(zap.String("op", "probe")).Info("packet")
	default:
		log.With(zap.String("op", "unknown")).Info("packet")
	}
}

func (b *bridge) logAppleTalkPacket(packet ethertalk.Packet) {
	log := b.log.With(zap.String("protocol", "ddp"))
	d := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Payload, &d)
	if err != nil {
		log.With(zap.Error(err)).Error("unmarshal failed")
		return
	}
	log = log.With(
		zap.String("dst", fmt.Sprintf("%d.%d.%d", d.DstNet, d.DstNode, d.DstSocket)),
		zap.String("src", fmt.Sprintf("%d.%d.%d", d.SrcNet, d.SrcNode, d.SrcSocket)),
		zap.Uint8("proto", d.Proto),
		zap.Uint16("cksum", d.Cksum),
	)

	log.With(zap.String("data", hex(d.Data))).Info("packet")
}

func hex(data []byte) string {
	buf := bytes.Buffer{}
	for i, b := range data {
		if i > 0 && i%4 == 0 {
			fmt.Fprint(&buf, " ")
		}
		fmt.Fprintf(&buf, "%02x", b)
	}
	return string(buf.Bytes())
}
