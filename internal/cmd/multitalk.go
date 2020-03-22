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

// multitalk binary implementation
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/sfiera/multitalk/internal/dbg"
	"github.com/sfiera/multitalk/internal/raw"
	"github.com/sfiera/multitalk/internal/tcp"
	"github.com/sfiera/multitalk/internal/udp"
	"github.com/sfiera/multitalk/pkg/ddp"
	"github.com/sfiera/multitalk/pkg/ethertalk"
)

const (
	versionString = "multitalk 0.1"
)

var (
	ether   = pflag.StringArrayP("ethertalk", "e", []string{}, "interface to bridge via EtherTalk")
	server  = pflag.StringArrayP("server", "s", []string{}, "server to bridge via TCP")
	multi   = pflag.StringArrayP("multicast", "m", []string{}, "interface to bridge via UDP multicast")
	debug   = pflag.BoolP("debug", "d", false, "log packets")
	version = pflag.BoolP("version", "v", false, "Display version & exit")

	defaultNet = ddp.Network(0xff00)
)

type (
	iface struct {
		Send chan<- ethertalk.Packet
		Recv <-chan ethertalk.Packet
	}

	bridge interface {
		Start(ctx context.Context) (
			send chan<- ethertalk.Packet,
			recv <-chan ethertalk.Packet,
		)
	}
)

func Main() {
	if *version {
		fmt.Println(versionString)
		os.Exit(0)
	}

	bridges, err := Bridges()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	Run(context.Background(), bridges)
}

func Run(ctx context.Context, bridges []bridge) {
	ifaces := []iface{}
	for _, b := range bridges {
		send, recv := b.Start(ctx)
		ifaces = append(ifaces, iface{send, recv})
	}

	for _, iface := range ifaces {
		sends := []chan<- ethertalk.Packet{}
		for _, other := range ifaces {
			if iface.Send != other.Send {
				sends = append(sends, other.Send)
			}
		}

		go func(recv <-chan ethertalk.Packet) {
			for packet := range recv {
				for _, send := range sends {
					send <- packet
				}
			}
		}(iface.Recv)
	}

	<-ctx.Done()
}

func Bridges() (bridges []bridge, _ error) {
	niface := len(*server) + len(*ether) + len(*multi)
	if niface == 0 {
		return nil, fmt.Errorf("no interfaces specified")
	} else if (niface == 1) && !*debug {
		return nil, fmt.Errorf("only one interface specified")
	}

	for _, s := range *server {
		tcp, err := tcp.TCPClient(s)
		if err != nil {
			return nil, err
		}
		bridges = append(bridges, tcp)
	}

	for _, dev := range *ether {
		et, err := raw.EtherTalk(dev)
		if err != nil {
			return nil, err
		}
		bridges = append(bridges, et)
	}

	for _, dev := range *multi {
		udp, err := udp.Multicast(dev, defaultNet)
		if err != nil {
			return nil, err
		}
		bridges = append(bridges, udp)
	}

	if *debug {
		bridges = append(bridges, dbg.Logger())
	}
	return
}
