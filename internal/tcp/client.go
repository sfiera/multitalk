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

// Communicates with TCP servers
package tcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/sfiera/multitalk/pkg/ethertalk"
)

type bridge struct {
	conn net.Conn
}

func TCPClient(server string) (*bridge, error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %s", server, err.Error())
	}
	return &bridge{conn}, nil
}

func (b *bridge) Start(ctx context.Context) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
) {
	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)
	go b.capture(ctx, recvCh)
	go b.transmit(sendCh)
	return sendCh, recvCh
}

func (b *bridge) transmit(sendCh <-chan ethertalk.Packet) {
	for packet := range sendCh {
		bin, err := ethertalk.Marshal(packet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcp send: %s\n", err.Error())
			continue
		}
		_ = binary.Write(b.conn, binary.BigEndian, len(bin))
		_, _ = b.conn.Write(bin)
	}
}

func (b *bridge) capture(ctx context.Context, recvCh chan<- ethertalk.Packet) {
	go func() {
		<-ctx.Done()
		b.conn.Close()
	}()
	defer close(recvCh)

	for {
		// receive a frame and send it out on the net
		length := uint32(0)
		err := binary.Read(b.conn, binary.BigEndian, &length)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcp recv: %s\n", err.Error())
			os.Exit(1)
		}

		if length > 4096 {
			fmt.Fprintf(os.Stderr, "Received length is invalid: %d vs %d\n", length, length)
			continue
		}
		// DebugLog("receiving packet of length: %u\n", length);

		data := make([]byte, length)
		_, err = b.conn.Read(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcp recv: %s\n", err.Error())
			os.Exit(1)
		}
		// DebugLog("Successfully received packet\n%s", "");

		packet := ethertalk.Packet{}
		err = ethertalk.Unmarshal(data, &packet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcp recv: %s\n", err.Error())
			continue
		}

		// Verify this is actually an AppleTalk related frame we've
		// received, in a vague attempt at not polluting the network
		// with unintended frames.
		// DebugLog("ethertalk.Packet frame type: %x\n", type);
		if !((packet.SNAPProto == ethertalk.AARPProto) ||
			(packet.SNAPProto == ethertalk.AppleTalkProto)) {
			// Not an appletalk or aarp frame, drop it.
			// DebugLog("Not an AppleTalk or AARP frame, dropping: %d\n", packet.Proto);
			continue
		}

		recvCh <- packet
	}
}
