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
package dbg

import (
	"fmt"
	"log"

	"github.com/sfiera/multitalk/pkg/ethertalk"
	"github.com/sfiera/multitalk/pkg/ethertalk/aarp"
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
			if packet.LinkHeader != ethertalk.SNAP {
				log.Printf(
					"%s <- %s: ????",
					ethAddr(packet.Dst), ethAddr(packet.Src),
				)
				continue
			}

			switch packet.SNAPProto {
			case ethertalk.AARP:
				logAARPPacket(packet)
			case ethertalk.AppleTalk:
				logAppleTalkPacket(packet)
			default:
				log.Printf(
					"%s <- %s: snap: ????",
					ethAddr(packet.Dst), ethAddr(packet.Src),
				)
			}
		}
	}()

	close(recvCh)

	return sendCh, recvCh
}

func logAARPPacket(packet ethertalk.Packet) {
	a := aarp.Packet{}
	err := aarp.Unmarshal(packet.Data, &a)
	if err != nil {
		log.Printf(
			"%s <- %s: snap: aarp: ????",
			ethAddr(packet.Dst), ethAddr(packet.Src),
		)
		return
	}

	opname := llapOps[a.Opcode]
	if opname == "" {
		log.Printf(
			"%s <- %s: snap: aarp: eth-llap %02x",
			ethAddr(packet.Dst), ethAddr(packet.Src),
			a.Opcode,
		)
		return
	}

	log.Printf(
		"%s <- %s: snap: aarp: eth-llap %s %s/%s -> %s/%s",
		ethAddr(packet.Dst), ethAddr(packet.Src),
		opname,
		ethAddr(a.Src.Hardware), atalkAddr(a.Src.Proto),
		ethAddr(a.Dst.Hardware), atalkAddr(a.Dst.Proto),
	)
}

func logAppleTalkPacket(packet ethertalk.Packet) {
	log.Printf(
		"%s <- %s: snap: atlk: %+v",
		ethAddr(packet.Dst), ethAddr(packet.Src),
		packet.Data,
	)
}

func ethAddr(addr ethertalk.EthAddr) string {
	return fmt.Sprintf(
		"%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
	)
}

func atalkAddr(addr aarp.AtalkAddr) string {
	return fmt.Sprintf("%d.%d", addr.Network, addr.Node)
}
