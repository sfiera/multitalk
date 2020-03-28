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
	"log"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

type bridge struct{}

func Logger() *bridge {
	return &bridge{}
}

func (b *bridge) Start(ctx context.Context) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
) {
	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)
	go b.capture(recvCh)
	go b.transmit(sendCh)
	return sendCh, recvCh
}

func (b *bridge) transmit(sendCh <-chan ethertalk.Packet) {
	for packet := range sendCh {
		switch packet.SNAPProto {
		case ethertalk.AARPProto:
			logAARPPacket(packet)
		case ethertalk.AppleTalkProto:
			logAppleTalkPacket(packet)
		}
	}
}

func (b *bridge) capture(recvCh chan<- ethertalk.Packet) {
	close(recvCh)
}

func logAARPPacket(packet ethertalk.Packet) {
	a := aarp.Packet{}
	err := aarp.Unmarshal(packet.Payload, &a)
	if err != nil {
		log.Printf("aarp: invalid payload")
		return
	} else if a.Header != aarp.EthernetLLAPBridging {
		log.Printf("aarp: not eth-llap bridging")
		return
	}
	switch a.Opcode {
	case aarp.RequestOp:
		log.Printf(
			"aarp rqst: %d.%d <- %d.%d",
			a.Dst.Proto.Network, a.Dst.Proto.Node, a.Src.Proto.Network, a.Src.Proto.Node)
	case aarp.ResponseOp:
		log.Printf(
			"aarp resp: %d.%d <- %d.%d",
			a.Dst.Proto.Network, a.Dst.Proto.Node, a.Src.Proto.Network, a.Src.Proto.Node)
	case aarp.ProbeOp:
		log.Printf(
			"aarp prob: %d.%d <- %d.%d",
			a.Dst.Proto.Network, a.Dst.Proto.Node, a.Src.Proto.Network, a.Src.Proto.Node)
	default:
		log.Printf(
			"aarp ????: %d.%d <- %d.%d",
			a.Dst.Proto.Network, a.Dst.Proto.Node, a.Src.Proto.Network, a.Src.Proto.Node)
	}
}

func logAppleTalkPacket(packet ethertalk.Packet) {
	d := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Payload, &d)
	if err != nil {
		log.Printf("ddp: invalid payload")
		return
	}
	log.Printf(
		"ddp: %d.%d.%d <- %d.%d.%d: %02x: %+v [%04x]",
		d.DstNet, d.DstNode, d.DstSocket, d.SrcNet, d.SrcNode, d.SrcSocket,
		d.Proto, d.Data, d.Cksum)
}
