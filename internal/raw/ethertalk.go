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

// Communicates with EtherTalk devices via libpcap
package raw

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/sfiera/multitalk/pkg/ethernet"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

type (
	bridge struct {
		dev         string
		mu          sync.Mutex
		local       []ethertalk.Packet
		capturer    capturer
		transmitter transmitter
	}

	capturer interface {
		ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	}

	transmitter interface {
		WritePacketData([]byte) error
	}
)

func EtherTalk(dev string) (b *bridge, err error) {
	b = &bridge{dev: dev}

	b.capturer, err = b.setupCapture(dev)
	if err != nil {
		return nil, err
	}

	b.transmitter, err = b.setupTransmit(dev)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (b *bridge) Start(ctx context.Context) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
) {
	sendCh := make(chan ethertalk.Packet)
	recvCh := make(chan ethertalk.Packet)
	go b.capture(recvCh)
	go b.transmit(sendCh)
	return sendCh, recvCh
}

func (b *bridge) setupCapture(dev string) (capturer, error) {
	capturer, err := pcap.OpenLive(dev, 4096, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("open dev %s: %s", dev, err.Error())
	}

	filter := "atalk or aarp"
	fp, err := capturer.CompileBPFFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("compile filter %s: %s", filter, err.Error())
	}

	err = capturer.SetBPFInstructionFilter(fp)
	if err != nil {
		return nil, fmt.Errorf("install filter %s: %s", filter, err.Error())
	}

	return capturer, nil
}

func (b *bridge) capture(ch chan<- ethertalk.Packet) {
	localAddrs := map[ethernet.Addr]bool{}
	for {
		data, ci, err := b.capturer.ReadPacketData()
		if err != nil {
			fmt.Fprintf(os.Stderr, "read packet %s: %s\n", b.dev, err.Error())
			os.Exit(5)
		}
		if ci.CaptureLength != ci.Length {
			// DebugLog("truncated packet! %s\n", "");
		}
		packet := ethertalk.Packet{}
		err = ethertalk.Unmarshal(data, &packet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "localtalk recv: %s\n", err.Error())
			continue
		}
		b.packet_handler(ch, packet, localAddrs)
	}
}

func (b *bridge) packet_handler(
	send chan<- ethertalk.Packet,
	packet ethertalk.Packet,
	localAddrs map[ethernet.Addr]bool,
) {
	// DebugLog("packet_handler entered%s", "\n")

	// Check to make sure the packet we just received wasn't sent
	// by us (the bridge), otherwise this is how loops happen
	b.mu.Lock()
	for i, np := range b.local {
		if ethertalk.Equal(&np, &packet) {
			last := len(b.local) - 1
			b.local[i] = b.local[last]
			b.local = b.local[:last]
			b.mu.Unlock()
			// DebugLog("packet_handler returned, skipping our own packet%s", "\n")
			return
		}
	}
	b.mu.Unlock()

	// Check to see if the destination address matches any addresses
	// in the list of source addresses we've seen on our network.
	// If it is, don't bother sending it over the bridge as the
	// recipient is local.
	if localAddrs[packet.Dst] {
		// DebugLog("packet_handler returned, skipping local packet%s", "\n")
		return
	}

	// Destination is remote, but originated locally, so we can add
	// the source address to our list.
	localAddrs[packet.Src] = true

	send <- packet
	// DebugLog("Wrote packet of size %d\n", len(packet))
}

func (b *bridge) setupTransmit(dev string) (transmitter, error) {
	// DebugLog("Using device: %s\n", dev);
	transmitter, err := pcap.OpenLive(dev, 1, false, 1000)
	if err != nil {
		return nil, fmt.Errorf("open dev %s: %s", dev, err.Error())
	}
	return transmitter, nil
}

func (b *bridge) transmit(ch <-chan ethertalk.Packet) {
	for packet := range ch {
		// printBuffer(packet)
		// We now have a frame, time to send it out.
		b.mu.Lock()
		b.local = append(b.local, packet)
		b.mu.Unlock()

		bin, err := ethertalk.Marshal(packet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "localtalk send: %s\n", err.Error())
			continue
		}
		err = b.transmitter.WritePacketData(bin)
		// DebugLog("pcap_sendpacket returned %d\n", pret);
		if err != nil {
			fmt.Fprintf(os.Stderr, "write packet: %s\n", err.Error())
		}
		// The capture thread will free these
	}
}
