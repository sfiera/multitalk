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
	"net"
	"os"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethernet"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

var (
	address = &net.UDPAddr{
		IP:   net.ParseIP("239.192.76.84"),
		Port: 1954,
	}

	defaultNet = uint16(0xff00)
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

	ethAddr := ethernet.Addr{}
	copy(ethAddr[:], i.HardwareAddr)

	conn, err := net.ListenMulticastUDP("udp", i, address)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %s", iface, err.Error())
	}

	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)

	go func(sendCh <-chan ethertalk.Packet) {
		for packet := range sendCh {
			_ = packet
		}
	}(sendCh)

	go func(recvCh chan<- ethertalk.Packet) {
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
				continue
			}

			packet.Data, err = ioutil.ReadAll(r)
			if err != nil {
				continue
			}

			out := convert(ethAddr, addr, packet)
			if out != nil {
				recvCh <- *out
			}
		}
	}(recvCh)

	return sendCh, recvCh, nil
}

func convert(ethAddr ethernet.Addr, addr *net.UDPAddr, packet LTOUPacket) *ethertalk.Packet {
	switch packet.Kind {
	case 0x01:
		return regDDP(ethAddr, addr, packet)
	case 0x02:
		return extDDP(ethAddr, addr, packet)
	case 0x81:
		return probe(ethAddr, addr, packet)
	case 0x82:
		return ack(ethAddr, addr, packet)
	default:
		return nil
	}
}

func regDDP(ethAddr ethernet.Addr, addr *net.UDPAddr, packet LTOUPacket) *ethertalk.Packet {
	d := ddp.Packet{}
	err := ddp.Unmarshal(packet.Data, &d)
	if err != nil {
		return nil
	}

	ext := ddp.ExtPacket{
		ExtHeader: ddp.ExtHeader{
			Size:    d.Size + 8,
			DstNet:  defaultNet,
			DstNode: packet.DstNode,
			DstPort: d.DstPort,
			SrcNet:  defaultNet,
			SrcNode: packet.SrcNode,
			SrcPort: d.SrcPort,
			Proto:   d.Proto,
		},
		Data: d.Data,
	}

	out, err := ethertalk.AppleTalk(ethAddr, ext)
	if err != nil {
		return nil
	}
	return out
}

func extDDP(ethAddr ethernet.Addr, addr *net.UDPAddr, packet LTOUPacket) *ethertalk.Packet {
	d := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Data, &d)
	if err != nil {
		return nil
	}
	out, err := ethertalk.AppleTalk(ethAddr, d)
	if err != nil {
		return nil
	}
	return out
}

func probe(ethAddr ethernet.Addr, addr *net.UDPAddr, packet LTOUPacket) *ethertalk.Packet {
	out, err := ethertalk.AARP(
		ethAddr,
		aarp.Probe(ethAddr, aarp.AtalkAddr{Network: defaultNet, Node: packet.DstNode}),
	)
	if err != nil {
		return nil
	}
	return out
}

func ack(ethAddr ethernet.Addr, addr *net.UDPAddr, packet LTOUPacket) *ethertalk.Packet {
	out, err := ethertalk.AARP(ethAddr, aarp.Response(
		aarp.AddrPair{
			Hardware: ethAddr,
			Proto:    aarp.AtalkAddr{Network: defaultNet, Node: packet.SrcNode},
		},
		aarp.AddrPair{
			Hardware: ethAddr,
			Proto:    aarp.AtalkAddr{Network: defaultNet, Node: packet.DstNode},
		},
	))
	if err != nil {
		return nil
	}
	return out
}
