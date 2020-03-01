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
package tcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/sfiera/multitalk/pkg/ethertalk"
)

func TCPClient(server string) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
	_ error,
) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %s", server, err.Error())
	}

	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)

	go func() {
		for packet := range sendCh {
			bin, err := ethertalk.Marshal(packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "tcp send: %s\n", err.Error())
				continue
			}
			_ = binary.Write(conn, binary.BigEndian, len(bin))
			_, _ = conn.Write(bin)
		}
	}()

	go func() {
		for {
			// receive a frame and send it out on the net
			length := uint32(0)
			err := binary.Read(conn, binary.BigEndian, &length)
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
			_, err = conn.Read(data)
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

			// Verify this is actuall an AppleTalk related frame we've
			// received, in a vague attempt at not polluting the network
			// with unintended frames.
			// DebugLog("ethertalk.Packet frame type: %x\n", type);
			if !((packet.Proto == 0x809b) || (packet.Proto == 0x80f3)) {
				// Not an appletalk or aarp frame, drop it.
				// DebugLog("Not an AppleTalk or AARP frame, dropping: %d\n", packet.Proto);
				continue
			}

			recvCh <- packet
		}
	}()

	return sendCh, recvCh, nil
}
