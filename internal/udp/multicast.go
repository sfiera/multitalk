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
package udp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

var (
	address = &net.UDPAddr{
		IP:   net.ParseIP("239.192.76.84"),
		Port: 1954,
	}
)

type (
	LTOUHeader struct {
		Pid              uint32
		DstNode, SrcNode uint8
		Kind             uint8
	}
	LTOUPacket struct {
		LTOUHeader
		Data []byte
	}
)

func Multicast(iface string) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
	_ error,
) {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s: %s", iface, err.Error())
	}

	conn, err := net.ListenMulticastUDP("udp", i, address)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %s", iface, err.Error())
	}

	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)

	go func() {
		for packet := range sendCh {
			_ = packet
		}
	}()

	go func() {
		bin := make([]byte, 700)
		for {
			n, addr, err := conn.ReadFromUDP(bin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "udp recv: %s\n", err.Error())
				os.Exit(1)
			}

			r := bytes.NewReader(bin[:n])
			packet := LTOUPacket{}
			err = binary.Read(r, binary.BigEndian, &packet.LTOUHeader)
			if err != nil {
				log.Printf("udp <- %s: ????", addr.String())
				continue
			}

			packet.Data, err = ioutil.ReadAll(r)
			if err != nil {
				log.Printf("udp <- %s: ????", addr.String())
				continue
			}

			switch packet.Kind {
			case 0x01:
				logDDP(addr, packet)
			case 0x02:
				logExtDDP(addr, packet)
			case 0x81:
				logControl(addr, packet, "enq")
			case 0x82:
				logControl(addr, packet, "ack")
			default:
				logUnknown(addr, packet)
			}
		}
	}()

	return sendCh, recvCh, nil
}

func logDDP(addr *net.UDPAddr, packet LTOUPacket) {
	d := ddp.Packet{}
	err := ddp.Unmarshal(packet.Data, &d)
	if err != nil {
		log.Printf(
			"udp <- %s.%08x: ddp %d <- %d ????",
			addr.String(), packet.Pid,
			packet.DstNode, packet.SrcNode,
		)
		return
	}

	log.Printf(
		"udp <- %s.%08x: ddp %d:%d <- %d:%d %02x: %+v",
		addr.String(), packet.Pid,
		packet.DstNode, d.DstPort,
		packet.SrcNode, d.SrcPort,
		d.Proto, d.Data,
	)
}

func logExtDDP(addr *net.UDPAddr, packet LTOUPacket) {
	d := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Data, &d)
	if err != nil {
		log.Printf(
			"udp <- %s.%08x: ddp %d <- %d [????]",
			addr.String(), packet.Pid,
			packet.DstNode, packet.SrcNode,
		)
		return
	}

	log.Printf(
		"udp <- %s.%08x: ddp %d.%d:%d <- %d.%d:%d [%04x] %02x: %+v",
		addr.String(), packet.Pid,
		d.DstNet, d.DstNode, d.DstPort,
		d.SrcNet, d.SrcNode, d.SrcPort,
		d.Cksum, d.Proto, d.Data,
	)
}

func logControl(addr *net.UDPAddr, packet LTOUPacket, what string) {
	log.Printf(
		"udp <- %s.%08x: %s %d <- %d",
		addr.String(), packet.Pid,
		what, packet.DstNode, packet.SrcNode,
	)
}

func logUnknown(addr *net.UDPAddr, packet LTOUPacket) {
	log.Printf(
		"udp <- %s.%08x: %02x %d <- %d: %+v",
		addr.String(), packet.Pid,
		packet.Kind, packet.DstNode, packet.SrcNode,
		packet.Data,
	)
}
