//
// Copyright (c) 2009 Rob Braun <bbraun@synack.net>
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
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/pflag"
)

const (
	versionString = "abridge 0.1"
)

var (
	dev     = pflag.StringP("interface", "i", "", "Specify the interface to bridge to")
	server  = pflag.StringP("server", "s", "127.0.0.1:9999", "Specify the server to connect to")
	version = pflag.BoolP("version", "v", false, "Display version & exit")

	localPacketMu sync.Mutex
	localPackets  [][]byte
)

type (
	addr [6]byte

	Interface struct {
		Send chan<- []byte
		Recv <-chan []byte
	}
)

func main() {
	pflag.Parse()

	if *version {
		fmt.Println(versionString)
		os.Exit(0)
	} else if *dev == "" {
		fmt.Fprintf(os.Stderr, "%s: missing required flag --interface\n", os.Args[0])
		os.Exit(1)
	}

	ch := make(chan bool)

	ifaces := Interfaces()

	for i, iface := range ifaces {
		sends := []chan<- []byte{}
		for j, other := range ifaces {
			if i != j {
				sends = append(sends, other.Send)
			}
		}

		go func(recv <-chan []byte) {
			defer close(ch)
			for packet := range recv {
				for _, send := range sends {
					send <- packet
				}
			}
		}(iface.Recv)
	}
	<-ch
}

func Interfaces() (ifaces []Interface) {
	srv, err := TCPServer(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	ifaces = append(ifaces, *srv)

	lcl, err := EtherTalk(*dev)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	ifaces = append(ifaces, *lcl)

	return
}

func TCPServer(server string) (*Interface, error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %s", server, err.Error())
	}

	sendCh := make(chan []byte)
	recvCh := make(chan []byte)

	go func() {
		for packet := range sendCh {
			_ = binary.Write(conn, binary.BigEndian, len(packet))
			_, _ = conn.Write(packet)
		}
	}()

	go func() {
		for {
			// receive a frame and send it out on the net
			length := uint32(0)
			err := binary.Read(conn, binary.BigEndian, &length)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read: %s\n", err.Error())
				os.Exit(1)
			}

			if length > 4096 {
				fmt.Fprintf(os.Stderr, "Received length is invalid: %d vs %d\n", length, length)
				continue
			}
			// DebugLog("receiving packet of length: %u\n", length);

			packet := make([]byte, length)
			_, err = conn.Read(packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read: %s\n", err.Error())
				os.Exit(1)
			}
			// DebugLog("Successfully received packet\n%s", "");

			/* 6 + 6 + 2 + 1 + 1 + 1 + 3 +2<type> + 4crc*/
			if len(packet) < 26 {
				// Too short to be a valid ethernet frame
				continue
			}

			// Verify this is actuall an AppleTalk related frame we've
			// received, in a vague attempt at not polluting the network
			// with unintended frames.
			frameType := frameType(packet)
			// DebugLog("Packet frame type: %x\n", type);
			if !((frameType == 0x809b) || (frameType == 0x80f3)) {
				// Not an appletalk or aarp frame, drop it.
				// DebugLog("Not an AppleTalk or AARP frame, dropping: %d\n", frameType);
				continue
			}

			recvCh <- packet
		}
	}()

	return &Interface{
		Send: sendCh,
		Recv: recvCh,
	}, nil
}

func EtherTalk(dev string) (*Interface, error) {
	recvCh, err := capture(dev)
	if err != nil {
		return nil, err
	}

	sendCh, err := transmit(dev)
	if err != nil {
		return nil, err
	}

	return &Interface{
		Send: sendCh,
		Recv: recvCh,
	}, nil
}

func capture(dev string) (<-chan []byte, error) {
	ch := make(chan []byte)

	// DebugLog("Using device: %s\n", dev)
	handle, err := pcap.OpenLive(dev, 4096, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open dev %s: %s", dev, err.Error())
	}

	filter := "atalk or aarp"
	fp, err := handle.CompileBPFFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("compile filter %s: %s", filter, err.Error())
	}

	err = handle.SetBPFInstructionFilter(fp)
	if err != nil {
		return nil, fmt.Errorf("install filter %s: %s", filter, err.Error())
	}

	go func(send chan<- []byte) {
		localAddrs := map[addr]bool{}
		for {
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				fmt.Fprintf(os.Stderr, "read packet %s: %s\n", dev, err.Error())
				os.Exit(5)
			}
			if ci.CaptureLength != ci.Length {
				// DebugLog("truncated packet! %s\n", "");
			}
			packet_handler(send, data, localAddrs)
		}
	}(ch)
	return ch, nil
}

func packet_handler(send chan<- []byte, packet []byte, localAddrs map[addr]bool) {
	// DebugLog("packet_handler entered%s", "\n")

	// Check to make sure the packet we just received wasn't sent
	// by us (the bridge), otherwise this is how loops happen
	localPacketMu.Lock()
	for i, np := range localPackets {
		if bytes.Compare(np, packet) == 0 {
			last := len(localPackets) - 1
			localPackets[i] = localPackets[last]
			localPackets = localPackets[:last]
			localPacketMu.Unlock()
			// DebugLog("packet_handler returned, skipping our own packet%s", "\n")
			return
		}
	}
	localPacketMu.Unlock()

	// anything less than this isn't a valid frame
	if len(packet) < 18 {
		// DebugLog("packet_handler returned, skipping invalid packet%s", "\n")
		return
	}

	// Check to see if the destination address matches any addresses
	// in the list of source addresses we've seen on our network.
	// If it is, don't bother sending it over the bridge as the
	// recipient is local.
	if localAddrs[dstAddr(packet)] {
		// DebugLog("packet_handler returned, skipping local packet%s", "\n")
		return
	}

	// Destination is remote, but originated locally, so we can add
	// the source address to our list.
	localAddrs[srcAddr(packet)] = true

	send <- packet
	// DebugLog("Wrote packet of size %d\n", len(packet))
}

func transmit(dev string) (chan<- []byte, error) {
	ch := make(chan []byte)

	// DebugLog("Using device: %s\n", dev);
	handle, err := pcap.OpenLive(dev, 1, false, 1000)
	if err != nil {
		return nil, fmt.Errorf("open dev %s: %s", dev, err.Error())
	}

	go func(recv <-chan []byte) {
		for packet := range recv {
			// printBuffer(packet)
			// We now have a frame, time to send it out.
			localPacketMu.Lock()
			localPackets = append(localPackets, packet)
			localPacketMu.Unlock()

			err = handle.WritePacketData(packet)
			// DebugLog("pcap_sendpacket returned %d\n", pret);
			if err != nil {
				fmt.Fprintf(os.Stderr, "write packet: %s\n", err.Error())
			}
			// The capture thread will free these
		}
	}(ch)
	return ch, nil
}

func srcAddr(packet []byte) (a addr) {
	copy(a[:], packet[6:12])
	return
}

func dstAddr(packet []byte) (a addr) {
	copy(a[:], packet[0:6])
	return
}

func frameType(packet []byte) uint16 {
	return binary.BigEndian.Uint16(packet[20:22])
}
