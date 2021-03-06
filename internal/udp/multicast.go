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

// Communicates with LocalTalk speakers via UDP multicast
package udp

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethernet"
	"github.com/sfiera/multitalk/pkg/ethertalk"
	"github.com/sfiera/multitalk/pkg/llap"
	"github.com/sfiera/multitalk/pkg/ltou"
)

type bridge struct {
	network ddp.Network

	pid   uint32
	iface *net.Interface
	eth   ethernet.Addr
	conn  *net.UDPConn

	nodes   map[ddp.Node]bool
	nodesMu sync.Mutex
}

func Multicast(iface string, network ddp.Network) (*bridge, error) {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %s", iface, err.Error())
	}

	b := bridge{
		network: network,
		pid:     uint32(os.Getpid()),
		iface:   i,
		nodes:   map[ddp.Node]bool{},
	}
	copy(b.eth[:], i.HardwareAddr)

	b.conn, err = net.ListenMulticastUDP("udp", i, ltou.MulticastAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %s", iface, err.Error())
	}
	return &b, nil
}

func (b *bridge) Start(ctx context.Context) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
) {
	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)
	go b.capture(ctx, recvCh)
	go b.transmit(sendCh, recvCh)
	return sendCh, recvCh
}

func (b *bridge) transmit(
	sendCh <-chan ethertalk.Packet,
	recvCh chan<- ethertalk.Packet,
) {
	for packet := range sendCh {
		conv, resp := b.etherTalkToUDP(packet)
		if resp != nil {
			recvCh <- *resp
			continue
		} else if conv == nil {
			fmt.Fprintf(os.Stderr, "send udp: conversion failed\n")
			continue
		}

		data, err := ltou.Marshal(*conv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "send udp: %s\n", err.Error())
			continue
		}

		_, err = b.conn.WriteToUDP(data, ltou.MulticastAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "send udp: %s\n", err.Error())
		}
	}
}

func (b *bridge) etherTalkToUDP(packet ethertalk.Packet) (
	converted *ltou.Packet,
	response *ethertalk.Packet,
) {
	switch packet.SNAPProto {
	case ethertalk.AppleTalkProto:
		return b.ddpToUDP(packet)
	case ethertalk.AARPProto:
		return b.aarpToUDP(packet)
	default:
		return nil, nil
	}
}

func (b *bridge) isLocal(net ddp.Network) bool {
	return net == 0 || net == b.network
}

func (b *bridge) ddpToUDP(packet ethertalk.Packet) (
	converted *ltou.Packet,
	response *ethertalk.Packet,
) {
	ext := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Payload, &ext)
	if err != nil {
		return nil, nil
	}

	if b.isLocal(ext.SrcNet) && b.isLocal(ext.DstNet) {
		short := ddp.ExtToShort(ext)
		result, err := ltou.AppleTalk(b.pid, ext.DstNode, ext.SrcNode, short)
		if err != nil {
			return nil, nil
		}
		return result, nil
	} else {
		result, err := ltou.ExtAppleTalk(b.pid, ext.DstNode, ext.SrcNode, ext)
		if err != nil {
			return nil, nil
		}
		return result, nil
	}
}

func (b *bridge) aarpToUDP(packet ethertalk.Packet) (
	converted *ltou.Packet,
	response *ethertalk.Packet,
) {
	a := aarp.Packet{}
	err := aarp.Unmarshal(packet.Payload, &a)
	if err != nil {
		return nil, nil
	}

	if !b.isLocal(a.Src.Proto.Network) || !b.isLocal(a.Dst.Proto.Network) {
		return nil, nil
	}

	switch a.Opcode {
	case aarp.ProbeOp:
		// “Is this AppleTalk node ID in use by anyone?”
		return ltou.Enq(b.pid, a.Dst.Proto.Node, a.Src.Proto.Node), nil

	case aarp.ResponseOp:
		// “Yes, sorry, I’m already using that node ID.”
		return ltou.Ack(b.pid, a.Dst.Proto.Node, a.Src.Proto.Node), nil

	case aarp.RequestOp:
		// Request to map an AppleTalk address to a hardware address (MAC).
		// Don’t translate to UDP, since there’s no corresponding request.
		// Check if the target machine is one that has broadcast UDP packets.
		// If it has, then report this machine’s hardware address as the
		// target for the queried AppleTalk address.
		if !b.isProxyForNode(a.Dst.Proto.Node) {
			return nil, nil
		}
		resp, err := ethertalk.AARP(b.eth, aarp.Response(aarp.AddrPair{
			Hardware: b.eth,
			Proto:    a.Dst.Proto,
		}, a.Src))
		if err != nil {
			return nil, nil
		}
		return nil, resp

	default:
		return nil, nil
	}
}

func (b *bridge) isProxyForNode(node ddp.Node) bool {
	b.nodesMu.Lock()
	defer b.nodesMu.Unlock()
	return b.nodes[node]
}

func (b *bridge) markProxyForNode(node ddp.Node) {
	b.nodesMu.Lock()
	defer b.nodesMu.Unlock()
	b.nodes[node] = true
}

func (b *bridge) capture(
	ctx context.Context,
	recvCh chan<- ethertalk.Packet,
) {
	go func() {
		<-ctx.Done()
		b.conn.Close()
	}()
	defer close(recvCh)

	bin := make([]byte, 700)
	for {
		n, addr, err := b.conn.ReadFromUDP(bin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "udp recv: %s\n", err.Error())
			os.Exit(1)
		}

		packet := ltou.Packet{}
		err = ltou.Unmarshal(bin[:n], &packet)
		if err != nil {
			continue
		}

		if b.isSender(addr, packet) {
			// If this bridge sent the packet, avoid a loop by ignoring
			// it when it’s received back again via multicast.
			continue
		}

		conv, resp := b.udpToEtherTalk(addr, packet)
		if resp != nil {
			data, err := ltou.Marshal(*resp)
			if err != nil {
				continue
			}
			_, err = b.conn.WriteToUDP(data, ltou.MulticastAddr)
			if err != nil {
				continue
			}
		} else if conv != nil {
			b.markProxyForNode(packet.LLAP.SrcNode)
			recvCh <- *conv
		}
	}
}

func (b *bridge) isSender(from *net.UDPAddr, packet ltou.Packet) bool {
	if packet.Pid != b.pid {
		return false
	}
	addrs, err := b.iface.Addrs()
	if err != nil {
		return true
	}
	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPAddr); ok {
			if ip.IP.Equal(from.IP) {
				return true
			}
		}
	}
	return false
}

func (b *bridge) udpToEtherTalk(addr *net.UDPAddr, packet ltou.Packet) (
	converted *ethertalk.Packet,
	response *ltou.Packet,
) {
	switch packet.LLAP.Kind {
	case llap.TypeDDP:
		return b.udpToDDP(addr, packet)
	case llap.TypeExtDDP:
		return b.udpToExtDDP(addr, packet)
	case llap.TypeEnq:
		return b.udpToProbe(addr, packet)
	case llap.TypeAck:
		return b.udpToAck(addr, packet)
	default:
		return nil, nil
	}
}

func (b *bridge) udpToDDP(addr *net.UDPAddr, packet ltou.Packet) (
	converted *ethertalk.Packet,
	response *ltou.Packet,
) {
	d := ddp.Packet{}
	err := ddp.Unmarshal(packet.LLAP.Payload, &d)
	if err != nil {
		return nil, nil
	}

	ext := ddp.ShortToExt(d, b.network, packet.LLAP.DstNode, packet.LLAP.SrcNode)
	out, err := ethertalk.AppleTalk(b.eth, ext)
	if err != nil {
		return nil, nil
	}
	return out, nil
}

func (b *bridge) udpToExtDDP(addr *net.UDPAddr, packet ltou.Packet) (
	converted *ethertalk.Packet,
	response *ltou.Packet,
) {
	d := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.LLAP.Payload, &d)
	if err != nil {
		return nil, nil
	}
	out, err := ethertalk.AppleTalk(b.eth, d)
	if err != nil {
		return nil, nil
	}
	return out, nil
}

func (b *bridge) udpToProbe(addr *net.UDPAddr, packet ltou.Packet) (
	converted *ethertalk.Packet,
	response *ltou.Packet,
) {
	out, err := ethertalk.AARP(
		b.eth,
		aarp.Probe(b.eth, ddp.Addr{Network: b.network, Node: packet.LLAP.DstNode}),
	)
	if err != nil {
		return nil, nil
	}
	return out, nil
}

func (b *bridge) udpToAck(addr *net.UDPAddr, packet ltou.Packet) (
	converted *ethertalk.Packet,
	response *ltou.Packet,
) {
	out, err := ethertalk.AARP(b.eth, aarp.Response(
		aarp.AddrPair{
			Hardware: b.eth,
			Proto:    ddp.Addr{Network: b.network, Node: packet.LLAP.SrcNode},
		},
		aarp.AddrPair{
			Hardware: b.eth,
			Proto:    ddp.Addr{Network: b.network, Node: packet.LLAP.DstNode},
		},
	))
	if err != nil {
		return nil, nil
	}
	return out, nil
}
