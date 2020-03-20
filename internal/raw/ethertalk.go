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

package raw

import (
	"fmt"
	"os"
	"sync"

	"github.com/google/gopacket/pcap"

	"github.com/sfiera/multitalk/pkg/ethernet"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

func EtherTalk(dev string) (
	send chan<- ethertalk.Packet,
	recv <-chan ethertalk.Packet,
	_ error,
) {
	localPacketMu := sync.Mutex{}
	localPackets := []ethertalk.Packet{}

	recvCh, err := capture(dev, &localPacketMu, &localPackets)
	if err != nil {
		return nil, nil, err
	}

	sendCh, err := transmit(dev, &localPacketMu, &localPackets)
	if err != nil {
		return nil, nil, err
	}

	return sendCh, recvCh, nil
}

func capture(dev string, mu *sync.Mutex, localPackets *[]ethertalk.Packet) (<-chan ethertalk.Packet, error) {
	ch := make(chan ethertalk.Packet)

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

	go func(send chan<- ethertalk.Packet) {
		localAddrs := map[ethernet.Addr]bool{}
		for {
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				fmt.Fprintf(os.Stderr, "read packet %s: %s\n", dev, err.Error())
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
			packet_handler(send, packet, localAddrs, mu, localPackets)
		}
	}(ch)
	return ch, nil
}

func packet_handler(
	send chan<- ethertalk.Packet,
	packet ethertalk.Packet,
	localAddrs map[ethernet.Addr]bool,
	mu *sync.Mutex,
	localPackets *[]ethertalk.Packet,
) {
	// DebugLog("packet_handler entered%s", "\n")

	// Check to make sure the packet we just received wasn't sent
	// by us (the bridge), otherwise this is how loops happen
	mu.Lock()
	for i, np := range *localPackets {
		if ethertalk.Equal(&np, &packet) {
			last := len(*localPackets) - 1
			(*localPackets)[i] = (*localPackets)[last]
			*localPackets = (*localPackets)[:last]
			mu.Unlock()
			// DebugLog("packet_handler returned, skipping our own packet%s", "\n")
			return
		}
	}
	mu.Unlock()

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

func transmit(dev string, mu *sync.Mutex, localPackets *[]ethertalk.Packet) (chan<- ethertalk.Packet, error) {
	ch := make(chan ethertalk.Packet)

	// DebugLog("Using device: %s\n", dev);
	handle, err := pcap.OpenLive(dev, 1, false, 1000)
	if err != nil {
		return nil, fmt.Errorf("open dev %s: %s", dev, err.Error())
	}

	go func(recv <-chan ethertalk.Packet) {
		for packet := range recv {
			// printBuffer(packet)
			// We now have a frame, time to send it out.
			mu.Lock()
			*localPackets = append(*localPackets, packet)
			mu.Unlock()

			bin, err := ethertalk.Marshal(packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "localtalk send: %s\n", err.Error())
				continue
			}
			err = handle.WritePacketData(bin)
			// DebugLog("pcap_sendpacket returned %d\n", pret);
			if err != nil {
				fmt.Fprintf(os.Stderr, "write packet: %s\n", err.Error())
			}
			// The capture thread will free these
		}
	}(ch)
	return ch, nil
}
