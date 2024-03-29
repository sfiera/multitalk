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

// definition of bridges
package bridge

import (
	"bytes"
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethertalk"
	"github.com/sfiera/multitalk/pkg/llap"
)

type (
	iface struct {
		send chan<- ethertalk.Packet
		recv <-chan ethertalk.Packet
	}

	packetFrom struct {
		packet *ethertalk.Packet
		send   chan<- ethertalk.Packet
	}

	Bridge interface {
		Start(ctx context.Context, log *zap.Logger) (
			send chan<- llap.Packet,
			recv <-chan llap.Packet,
		)
	}

	ExtBridge interface {
		Start(ctx context.Context, log *zap.Logger) (
			send chan<- ethertalk.Packet,
			recv <-chan ethertalk.Packet,
		)
	}

	Group struct {
		log    *zap.Logger
		recvCh chan func(*Group)
		sendCh []chan<- ethertalk.Packet
	}
)

func NewGroup(log *zap.Logger) *Group {
	return &Group{
		log,
		make(chan func(*Group)),
		nil,
	}
}

func (g *Group) Add(send chan<- ethertalk.Packet, recv <-chan ethertalk.Packet) {
	go func() {
		g.recvCh <- add(send)
		for pak := range recv {
			g.recvCh <- broadcast(pak, send)
		}
		g.recvCh <- remove(send)
	}()
}

func (g *Group) Run() {
	for fn := range g.recvCh {
		fn(g)
	}
}

func broadcast(pak ethertalk.Packet, send chan<- ethertalk.Packet) func(g *Group) {
	return func(g *Group) {
		switch pak.SNAPProto {
		case ethertalk.AARPProto:
			g.logAARPPacket(pak)
		case ethertalk.AppleTalkProto:
			g.logAppleTalkPacket(pak)
		}
		for _, sendCh := range g.sendCh {
			if sendCh != send {
				sendCh <- pak
			}
		}
	}
}

func add(send chan<- ethertalk.Packet) func(g *Group) {
	return func(g *Group) {
		g.sendCh = append(g.sendCh, send)
	}
}

func remove(send chan<- ethertalk.Packet) func(g *Group) {
	return func(g *Group) {
		var newCh []chan<- ethertalk.Packet
		for _, ch := range g.sendCh {
			if ch != send {
				newCh = append(newCh, ch)
			}
		}
		g.sendCh = newCh
		close(send)
	}
}

func (g *Group) logAARPPacket(packet ethertalk.Packet) {
	log := g.log.With(zap.String("protocol", "aarp"))
	a := aarp.Packet{}
	err := aarp.Unmarshal(packet.Payload, &a)
	if err != nil {
		log.With(zap.Error(err)).Error("unmarshal failed")
		return
	}

	if ce := log.Check(zap.DebugLevel, "packet"); ce != nil {
		ce.Write(
			zap.String("dst", fmt.Sprintf("%d.%d", a.Dst.Proto.Network, a.Dst.Proto.Node)),
			zap.String("src", fmt.Sprintf("%d.%d", a.Src.Proto.Network, a.Src.Proto.Node)),
		)

		switch a.Opcode {
		case aarp.RequestOp:
			ce.Write(zap.String("op", "request"))
		case aarp.ResponseOp:
			ce.Write(zap.String("op", "response"))
		case aarp.ProbeOp:
			ce.Write(zap.String("op", "probe"))
		default:
			ce.Write(zap.Uint16("op", uint16(a.Opcode)))
		}
	}
}

func (g *Group) logAppleTalkPacket(packet ethertalk.Packet) {
	log := g.log.With(zap.String("protocol", "ddp"))
	d := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Payload, &d)
	if err != nil {
		log.With(zap.Error(err)).Error("unmarshal failed")
		return
	}

	if ce := log.Check(zap.DebugLevel, "packet"); ce != nil {
		ce.Write(
			zap.String("dst", fmt.Sprintf("%d.%d.%d", d.DstNet, d.DstNode, d.DstSocket)),
			zap.String("src", fmt.Sprintf("%d.%d.%d", d.SrcNet, d.SrcNode, d.SrcSocket)),
			ddpProto("proto", d.Proto),
			zap.Uint16("cksum", d.Cksum),
			zap.String("data", hex(d.Data)),
		)
	}
}

func ddpProto(key string, val uint8) zap.Field {
	switch val {
	case ddp.ProtoRTMPResp:
		return zap.String("proto", "rtmp/resp")
	case ddp.ProtoNBP:
		return zap.String("proto", "nbp")
	case ddp.ProtoATP:
		return zap.String("proto", "atp")
	case ddp.ProtoAEP:
		return zap.String("proto", "aep")
	case ddp.ProtoRTMPReq:
		return zap.String("proto", "rtmp/req")
	case ddp.ProtoZIP:
		return zap.String("proto", "zip")
	case ddp.ProtoADSP:
		return zap.String("proto", "adsp")
	default:
		return zap.Uint8("proto", val)
	}
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
