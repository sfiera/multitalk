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

	"github.com/sfiera/multitalk/internal/bridge"
	"github.com/sfiera/multitalk/pkg/llap"
	"github.com/sfiera/multitalk/pkg/ltou"
	"go.uber.org/zap"
)

type multicast struct {
	pid   uint32
	iface *net.Interface
	conn  *net.UDPConn
}

func Multicast(iface string) (bridge.Bridge, []byte, error) {
	i, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s: %s", iface, err.Error())
	}

	m := multicast{
		pid:   uint32(os.Getpid()),
		iface: i,
	}

	m.conn, err = net.ListenMulticastUDP("udp", i, ltou.MulticastAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %s", iface, err.Error())
	}
	return &m, i.HardwareAddr, nil
}

func pipe[T any](ch chan T) (<-chan T, chan<- T) { return ch, ch }

func (b *multicast) Start(ctx context.Context, log *zap.Logger) (
	send chan<- llap.Packet,
	recv <-chan llap.Packet,
) {
	log = log.With(
		zap.String("bridge", "udp"),
		zap.String("iface", b.iface.Name),
	)
	sendInCh, sendOutCh := pipe(make(chan llap.Packet))
	recvInCh, recvOutCh := pipe(make(chan llap.Packet))
	go b.capture(ctx, log, recvOutCh)
	go b.transmit(ctx, log, sendInCh)
	return sendOutCh, recvInCh
}

func (b *multicast) transmit(
	ctx context.Context,
	log *zap.Logger,
	llapCh <-chan llap.Packet,
) {
	for packet := range llapCh {
		data, err := ltou.Marshal(ltou.Packet{
			Header: ltou.Header{Pid: b.pid},
			LLAP:   packet,
		})
		if err != nil {
			log.With(zap.Error(err)).Error("marshal failed")
			continue
		}

		_, err = b.conn.WriteToUDP(data, ltou.MulticastAddr)
		if err != nil {
			log.With(zap.Error(err)).Error("send failed")
		}
	}
}

func (b *multicast) capture(
	ctx context.Context,
	log *zap.Logger,
	recvCh chan<- llap.Packet,
) {
	defer close(recvCh)
	go func() {
		<-ctx.Done()
		b.conn.Close()
	}()

	bin := make([]byte, 700)
	for {
		n, addr, err := b.conn.ReadFromUDP(bin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "udp recv: %s\n", err.Error())
			return
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

		recvCh <- packet.LLAP
	}
}

func (b *multicast) isSender(from *net.UDPAddr, packet ltou.Packet) bool {
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
