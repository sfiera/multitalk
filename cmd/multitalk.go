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
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/pflag"
)

const (
	versionString = "multitalk 0.1"
)

var (
	ether   = pflag.StringArrayP("ethertalk", "e", []string{}, "interface to bridge via EtherTalk")
	server  = pflag.StringArrayP("server", "s", []string{}, "server to bridge via TCP")
	multi   = pflag.StringArrayP("multicast", "m", []string{}, "interface to bridge via UDP multicast")
	version = pflag.BoolP("version", "v", false, "Display version & exit")

	SNAP = LinkHeader{0xAA, 0xAA, 0x03}
)

type (
	Interface struct {
		Send chan<- Packet
		Recv <-chan Packet
	}

	EthAddr   [6]byte
	EthHeader struct {
		Dst, Src EthAddr
		Size     uint16
	}
	LinkHeader struct {
		DSAP, SSAP byte
		Control    byte
	}
	SNAPHeader struct {
		OUI   [3]byte
		Proto uint16
	}
	Packet struct {
		EthHeader
		LinkHeader
		SNAPHeader
		Data []byte
		Pad  []byte
	}
)

// Unmarshals a packet from bytes.
func EthUnmarshal(data []byte, pak *Packet) error {
	r := bytes.NewReader(data)

	err := binary.Read(r, binary.BigEndian, &pak.EthHeader)
	if err != nil {
		return fmt.Errorf("read eth header: %s", err.Error())
	}

	err = binary.Read(r, binary.BigEndian, &pak.LinkHeader)
	if err != nil {
		return fmt.Errorf("read link header: %s", err.Error())
	} else if pak.LinkHeader != SNAP {
		return fmt.Errorf("read link header: not SNAP")
	}

	err = binary.Read(r, binary.BigEndian, &pak.SNAPHeader)
	if err != nil {
		return fmt.Errorf("read snap header: %s", err.Error())
	}

	pak.Data = make([]byte, pak.Size-8) // 8 = size of link + snap header
	n, err := r.Read(pak.Data)
	if err != nil {
		return fmt.Errorf("read data: %s", err.Error())
	} else if n < int(pak.Size) {
		return fmt.Errorf("read data: incomplete data")
	}

	pak.Pad, err = ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read padding: %s", err.Error())
	}

	return nil
}

// Marshals a packet to bytes.
func EthMarshal(pak Packet) ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 22+len(pak.Data)+len(pak.Pad)))
	err := binary.Write(w, binary.BigEndian, pak.EthHeader)
	if err != nil {
		return nil, fmt.Errorf("write eth header: %s", err.Error())
	}

	err = binary.Write(w, binary.BigEndian, pak.LinkHeader)
	if err != nil {
		return nil, fmt.Errorf("write link header: %s", err.Error())
	}

	err = binary.Write(w, binary.BigEndian, pak.SNAPHeader)
	if err != nil {
		return nil, fmt.Errorf("write snap header: %s", err.Error())
	}

	n, err := w.Write(pak.Data)
	if err != nil {
		return nil, fmt.Errorf("write data: %s", err.Error())
	} else if n < int(pak.Size) {
		return nil, fmt.Errorf("write data: incomplete data")
	}

	n, err = w.Write(pak.Pad)
	if err != nil {
		return nil, fmt.Errorf("write padding: %s", err.Error())
	} else if n < int(pak.Size) {
		return nil, fmt.Errorf("write padding: incomplete data")
	}

	return w.Bytes(), nil
}

// Returns true if two packets are equal. Ignores padding.
func EthEqual(a, b *Packet) bool {
	return ((a.EthHeader == b.EthHeader) &&
		(a.LinkHeader == b.LinkHeader) &&
		(a.SNAPHeader == b.SNAPHeader) &&
		(bytes.Compare(a.Data, b.Data) == 0))
}

func main() {
	pflag.Parse()

	if *version {
		fmt.Println(versionString)
		os.Exit(0)
	}

	ch := make(chan bool)

	ifaces, err := Interfaces()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	for i, iface := range ifaces {
		sends := []chan<- Packet{}
		for j, other := range ifaces {
			if i != j {
				sends = append(sends, other.Send)
			}
		}

		go func(recv <-chan Packet) {
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

func Interfaces() (ifaces []Interface, _ error) {
	niface := len(*server) + len(*ether) + len(*multi)
	if niface == 0 {
		return nil, fmt.Errorf("no interfaces specified")
	} else if niface == 1 {
		return nil, fmt.Errorf("only one interface specified")
	}

	for _, s := range *server {
		srv, err := TCPServer(s)
		if err != nil {
			return nil, err
		}
		ifaces = append(ifaces, *srv)
	}

	for _, dev := range *ether {
		lcl, err := EtherTalk(dev)
		if err != nil {
			return nil, err
		}
		ifaces = append(ifaces, *lcl)
	}

	return
}

func TCPServer(server string) (*Interface, error) {
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %s", server, err.Error())
	}

	sendCh := make(chan Packet)
	recvCh := make(chan Packet)

	go func() {
		for packet := range sendCh {
			bin, err := EthMarshal(packet)
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

			packet := Packet{}
			err = EthUnmarshal(data, &packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "tcp recv: %s\n", err.Error())
				continue
			}

			// Verify this is actuall an AppleTalk related frame we've
			// received, in a vague attempt at not polluting the network
			// with unintended frames.
			// DebugLog("Packet frame type: %x\n", type);
			if !((packet.Proto == 0x809b) || (packet.Proto == 0x80f3)) {
				// Not an appletalk or aarp frame, drop it.
				// DebugLog("Not an AppleTalk or AARP frame, dropping: %d\n", packet.Proto);
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
	localPacketMu := sync.Mutex{}
	localPackets := []Packet{}

	recvCh, err := capture(dev, &localPacketMu, &localPackets)
	if err != nil {
		return nil, err
	}

	sendCh, err := transmit(dev, &localPacketMu, &localPackets)
	if err != nil {
		return nil, err
	}

	return &Interface{
		Send: sendCh,
		Recv: recvCh,
	}, nil
}

func capture(dev string, mu *sync.Mutex, localPackets *[]Packet) (<-chan Packet, error) {
	ch := make(chan Packet)

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

	go func(send chan<- Packet) {
		localAddrs := map[EthAddr]bool{}
		for {
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				fmt.Fprintf(os.Stderr, "read packet %s: %s\n", dev, err.Error())
				os.Exit(5)
			}
			if ci.CaptureLength != ci.Length {
				// DebugLog("truncated packet! %s\n", "");
			}
			packet := Packet{}
			err = EthUnmarshal(data, &packet)
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
	send chan<- Packet,
	packet Packet,
	localAddrs map[EthAddr]bool,
	mu *sync.Mutex,
	localPackets *[]Packet,
) {
	// DebugLog("packet_handler entered%s", "\n")

	// Check to make sure the packet we just received wasn't sent
	// by us (the bridge), otherwise this is how loops happen
	mu.Lock()
	for i, np := range *localPackets {
		if EthEqual(&np, &packet) {
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

func transmit(dev string, mu *sync.Mutex, localPackets *[]Packet) (chan<- Packet, error) {
	ch := make(chan Packet)

	// DebugLog("Using device: %s\n", dev);
	handle, err := pcap.OpenLive(dev, 1, false, 1000)
	if err != nil {
		return nil, fmt.Errorf("open dev %s: %s", dev, err.Error())
	}

	go func(recv <-chan Packet) {
		for packet := range recv {
			// printBuffer(packet)
			// We now have a frame, time to send it out.
			mu.Lock()
			*localPackets = append(*localPackets, packet)
			mu.Unlock()

			bin, err := EthMarshal(packet)
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
