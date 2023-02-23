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
	"go.uber.org/zap"

	"github.com/sfiera/multitalk/internal/bridge"
	"github.com/sfiera/multitalk/internal/raw"
	"github.com/sfiera/multitalk/internal/serial"
	"github.com/sfiera/multitalk/internal/tcp"
	"github.com/sfiera/multitalk/internal/udp"
	"github.com/sfiera/multitalk/pkg/ddp"
)

const (
	versionString = "multitalk 0.2.0"
)

var (
	ether   = pflag.StringArrayP("ethertalk", "e", []string{}, "interface to bridge via EtherTalk")
	multi   = pflag.StringArrayP("multicast", "m", []string{}, "interface to bridge via UDP multicast")
	tash    = pflag.StringArrayP("serial", "s", []string{}, "serial device to bridge via TashTalk")
	client  = pflag.StringArrayP("tcp-client", "t", []string{}, "address to dial via TCP")
	server  = pflag.StringArrayP("tcp-server", "T", []string{}, "address to listen via TCP")
	network = pflag.Uint16P("network", "n", 0xff00, "network number for LToU bridging")
	debug   = pflag.BoolP("debug", "d", false, "log packets")
	version = pflag.BoolP("version", "v", false, "Display version & exit")
)

func Main() {
	if *version {
		fmt.Println(versionString)
		os.Exit(0)
	}

	cfg := zap.NewDevelopmentConfig()
	if !*debug {
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	log, err := cfg.Build()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	g := bridge.NewGroup(log)
	err = bridges(context.Background(), log, g)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	g.Run()
}

func bridges(ctx context.Context, log *zap.Logger, grp *bridge.Group) error {
	niface := len(*client) + len(*server) + len(*ether) + len(*multi) + len(*tash)
	if niface == 0 {
		return fmt.Errorf("no interfaces specified")
	} else if (niface == 1) && (len(*server) == 0) && !*debug {
		return fmt.Errorf("only one interface specified")
	}

	for _, dev := range *ether {
		et, err := raw.EtherTalk(dev)
		if err != nil {
			return err
		}
		grp.Add(et.Start(ctx, log))
	}

	for _, dev := range *multi {
		m, hwAddr, err := udp.Multicast(dev)
		if err != nil {
			return err
		}
		grp.Add(bridge.Extend(m, ddp.Network(*network), hwAddr).Start(ctx, log))
	}

	for _, dev := range *tash {
		tt, hwAddr, err := serial.TashTalk(dev)
		if err != nil {
			return err
		}
		grp.Add(bridge.Extend(tt, ddp.Network(*network), hwAddr).Start(ctx, log))
	}

	for _, s := range *client {
		tcp, err := tcp.TCPClient(s)
		if err != nil {
			return err
		}
		grp.Add(tcp.Start(ctx, log))
	}

	for _, s := range *server {
		tcp, err := tcp.TCPServer(s)
		if err != nil {
			return err
		}
		tcp.Serve(ctx, log, grp)
	}

	return nil
}
