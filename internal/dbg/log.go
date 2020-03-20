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

package dbg

import (
	"fmt"
	"log"
	"strings"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethernet"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

var (
	llapOps = map[uint16]string{
		aarp.RequestOp:  "request",
		aarp.ResponseOp: "response",
		aarp.ProbeOp:    "probe",
	}
)

func Logger() (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
) {
	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)

	go func() {
		for packet := range sendCh {
			components := []string{
				fmt.Sprintf("%s <- %s", ethAddr(packet.Dst), ethAddr(packet.Src)),
			}
			log.Print(strings.Join(logSnap(packet, components), ": "))
		}
	}()

	close(recvCh)

	return sendCh, recvCh
}

func logSnap(packet ethertalk.Packet, components []string) []string {
	if packet.LinkHeader != ethertalk.SNAP {
		return append(components, "????")
	}
	components = append(components, "snap")

	switch packet.SNAPProto {
	case ethertalk.AARPProto:
		return logAARPPacket(packet, components)
	case ethertalk.AppleTalkProto:
		return logAppleTalkPacket(packet, components)
	default:
		return append(components, "????")
	}
}

func logAARPPacket(packet ethertalk.Packet, components []string) []string {
	components = append(components, "aarp")
	a := aarp.Packet{}
	err := aarp.Unmarshal(packet.Data, &a)
	if err != nil {
		return append(components, "????")
	}

	opname := llapOps[a.Opcode]
	if opname == "" {
		return append(components, fmt.Sprintf("eth-llap %02x", a.Opcode))
	}
	return append(components, fmt.Sprintf(
		"eth-llap %s %s/%s -> %s/%s",
		opname,
		ethAddr(a.Src.Hardware), atalkAddr(a.Src.Proto),
		ethAddr(a.Dst.Hardware), atalkAddr(a.Dst.Proto)))
}

func logAppleTalkPacket(packet ethertalk.Packet, components []string) []string {
	components = append(components, "atlk")
	d := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Data, &d)
	if err != nil {
		return append(components, "????")
	}

	components = append(components, fmt.Sprintf(
		"ddp [%04x] %d.%d:%d <- %d.%d:%d %02x",
		d.Cksum,
		d.DstNet, d.DstNode, d.DstSocket,
		d.SrcNet, d.SrcNode, d.SrcSocket,
		d.Proto,
	))
	return append(components, fmt.Sprintf("%+v", d.Data))
}

func ethAddr(addr ethernet.Addr) string {
	return fmt.Sprintf(
		"%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
	)
}

func atalkAddr(addr ddp.Addr) string {
	return fmt.Sprintf("%d.%d", addr.Network, addr.Node)
}
