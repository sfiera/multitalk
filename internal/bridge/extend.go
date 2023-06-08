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

package bridge

import (
	"context"
	"sync"
	"fmt"

	"github.com/sfiera/multitalk/pkg/aarp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethernet"
	"github.com/sfiera/multitalk/pkg/ethertalk"
	"github.com/sfiera/multitalk/pkg/llap"
	"go.uber.org/zap"
)

type router struct {
	network ddp.Network

	nodes   map[ddp.Node]bool
	nodesMu sync.Mutex

	eth ethernet.Addr

	bridge Bridge
}

// Extend converts a Bridge into an ExtBridge.
//
// The provided network is assumed to be the network for nodes on that bridge.
//
// TODO: implement router features, so that nodes on the network
// are properly aware of the network topology.
func Extend(b Bridge, network ddp.Network, hwAddr []byte) ExtBridge {
	r := router{
		network: network,
		nodes:   map[ddp.Node]bool{},
		bridge:  b,
	}
	copy(r.eth[:], hwAddr)
	return &r
}

func (r *router) Start(ctx context.Context, log *zap.Logger) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
) {
	sendLLAPOutCh, recvLLAPInCh := r.bridge.Start(ctx, log)
	sendELAPInCh, sendELAPOutCh := pipe(make(chan ethertalk.Packet))
	recvELAPInCh, recvELAPOutCh := pipe(make(chan ethertalk.Packet))
	go r.translateCapture(ctx, log, recvLLAPInCh, recvELAPOutCh)
	go r.translateTransmit(ctx, log, sendELAPInCh, sendLLAPOutCh, recvELAPOutCh)
	return sendELAPOutCh, recvELAPInCh
}

func (r *router) translateTransmit(
	ctx context.Context,
	log *zap.Logger,
	elapCh <-chan ethertalk.Packet,
	llapCh chan<- llap.Packet,
	respCh chan<- ethertalk.Packet,
) {
	for packet := range elapCh {
		llap, resp, err := r.elapToLLAP(packet)
		if resp != nil {
			respCh <- *resp
			continue
		} else if llap == nil {
			log.Error(fmt.Sprintf("convert failed: err %v", err))
			continue
		}
		llapCh <- *llap
	}
}

func (r *router) elapToLLAP(packet ethertalk.Packet) (
	converted *llap.Packet,
	response *ethertalk.Packet,
	e error,
) {
	switch packet.SNAPProto {
	case ethertalk.AppleTalkProto:
		c, err := r.elapToLLAPDDP(packet)
		return c, nil, err

	case ethertalk.AARPProto:
		c, r := r.elapToLLAPAARP(packet)
		return c, r, nil

	default:
		return nil, nil, nil
	}
}

func (r *router) isLocal(net ddp.Network) bool {
	return net == 0 || net == r.network
}

func (r *router) elapToLLAPDDP(packet ethertalk.Packet) (*llap.Packet, error) {
	ext := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Payload, &ext)
	if err != nil {
		return nil, err
	}

	if r.isLocal(ext.SrcNet) && r.isLocal(ext.DstNet) {
		short := ddp.ExtToShort(ext)
		result, err := llap.AppleTalk(ext.DstNode, ext.SrcNode, short)
		if err != nil {
			return nil, err
		}
		return result, nil
	} else {
		result, err := llap.ExtAppleTalk(ext.DstNode, ext.SrcNode, ext)
		if err != nil {
			return nil, err
		}
		return result, nil
	}
}

func (r *router) elapToLLAPAARP(packet ethertalk.Packet) (
	converted *llap.Packet,
	response *ethertalk.Packet,
) {
	a := aarp.Packet{}
	err := aarp.Unmarshal(packet.Payload, &a)
	if err != nil {
		return nil, nil
	}

	if !r.isLocal(a.Src.Proto.Network) || !r.isLocal(a.Dst.Proto.Network) {
		return nil, nil
	}

	switch a.Opcode {
	case aarp.ProbeOp:
		// “Is this AppleTalk node ID in use by anyone?”
		return llap.Enq(a.Dst.Proto.Node, a.Src.Proto.Node), nil

	case aarp.ResponseOp:
		// “Yes, sorry, I’m already using that node ID.”
		return llap.Ack(a.Dst.Proto.Node, a.Src.Proto.Node), nil

	case aarp.RequestOp:
		// Request to map an AppleTalk address to a hardware address (MAC).
		// Don’t translate to UDP, since there’s no corresponding request.
		// Check if the target machine is one that has broadcast UDP packets.
		// If it has, then report this machine’s hardware address as the
		// target for the queried AppleTalk address.
		if !r.isProxyForNode(a.Dst.Proto.Node) {
			return nil, nil
		}
		resp, err := ethertalk.AARP(r.eth, aarp.Response(aarp.AddrPair{
			Hardware: r.eth,
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

func (r *router) isProxyForNode(node ddp.Node) bool {
	r.nodesMu.Lock()
	defer r.nodesMu.Unlock()
	return r.nodes[node]
}

func (r *router) markProxyForNode(node ddp.Node) {
	r.nodesMu.Lock()
	defer r.nodesMu.Unlock()
	r.nodes[node] = true
}

func (r *router) translateCapture(
	ctx context.Context,
	log *zap.Logger,
	llapCh <-chan llap.Packet,
	elapCh chan<- ethertalk.Packet,
) {
	for packet := range llapCh {
		conv := r.llapToELAP(packet)
		if conv != nil {
			r.markProxyForNode(packet.SrcNode)
			elapCh <- *conv
		}
	}
}

func (r *router) llapToELAP(packet llap.Packet) *ethertalk.Packet {
	switch packet.Kind {
	case llap.TypeDDP:
		return r.llapToELAPDDP(packet)
	case llap.TypeExtDDP:
		return r.llapToELAPExtDDP(packet)
	case llap.TypeEnq:
		return r.llapToELAPProbe(packet)
	case llap.TypeAck:
		return r.llapToELAPAck(packet)
	default:
		return nil
	}
}

func (r *router) llapToELAPDDP(packet llap.Packet) *ethertalk.Packet {
	d := ddp.Packet{}
	err := ddp.Unmarshal(packet.Payload, &d)
	if err != nil {
		return nil
	}

	ext := ddp.ShortToExt(d, r.network, packet.DstNode, packet.SrcNode)
	out, err := ethertalk.AppleTalk(r.eth, ext)
	if err != nil {
		return nil
	}
	return out
}

func (r *router) llapToELAPExtDDP(packet llap.Packet) *ethertalk.Packet {
	d := ddp.ExtPacket{}
	err := ddp.ExtUnmarshal(packet.Payload, &d)
	if err != nil {
		return nil
	}
	out, err := ethertalk.AppleTalk(r.eth, d)
	if err != nil {
		return nil
	}
	return out
}

func (r *router) llapToELAPProbe(packet llap.Packet) *ethertalk.Packet {
	out, err := ethertalk.AARP(
		r.eth,
		aarp.Probe(r.eth, ddp.Addr{Network: r.network, Node: packet.DstNode}),
	)
	if err != nil {
		return nil
	}
	return out
}

func (r *router) llapToELAPAck(packet llap.Packet) *ethertalk.Packet {
	out, err := ethertalk.AARP(r.eth, aarp.Response(
		aarp.AddrPair{
			Hardware: r.eth,
			Proto:    ddp.Addr{Network: r.network, Node: packet.SrcNode},
		},
		aarp.AddrPair{
			Hardware: r.eth,
			Proto:    ddp.Addr{Network: r.network, Node: packet.DstNode},
		},
	))
	if err != nil {
		return nil
	}
	return out
}

func pipe[T any](ch chan T) (<-chan T, chan<- T) { return ch, ch }
