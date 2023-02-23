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

// Package serial communicates with a TashTalk unit over serial.
package serial

import (
	"context"
	"fmt"
	"io"

	"github.com/sfiera/multitalk/internal/bridge"
	"github.com/sfiera/multitalk/pkg/llap"
	"github.com/sfiera/multitalk/pkg/tash"
	"github.com/tarm/serial"
	"go.uber.org/zap"
)

type tt struct {
	device string
	port   *serial.Port
	dec    tash.Decoder
	enc    tash.Encoder
}

func TashTalk(device string) (bridge.Bridge, []byte, error) {
	conf := &serial.Config{Name: device, Baud: 1000000}
	port, err := serial.OpenPort(conf)
	if err != nil {
		return nil, nil, fmt.Errorf("tash open %s: %w", device, err)
	}

	return &tt{
		device: device,
		port:   port,
		dec:    tash.NewDecoder(port),
		enc:    tash.NewEncoder(port),
	}, nil, nil
}

func pipe[T any](ch chan T) (<-chan T, chan<- T) { return ch, ch }

func (t *tt) Start(ctx context.Context, log *zap.Logger) (
	send chan<- llap.Packet,
	recv <-chan llap.Packet,
) {
	log = log.With(
		zap.String("bridge", "udp"),
		zap.String("device", t.device),
	)
	sendInCh, sendOutCh := pipe(make(chan llap.Packet))
	recvInCh, recvOutCh := pipe(make(chan llap.Packet))
	go t.read(ctx, log, recvOutCh)
	go t.write(ctx, log, sendInCh)
	return sendOutCh, recvInCh
}

func (t *tt) write(
	ctx context.Context,
	log *zap.Logger,
	llapCh <-chan llap.Packet,
) {
	for packet := range llapCh {
		err := t.enc.Encode(packet)
		if err != nil {
			log.With(zap.Error(err)).Error("send failed")
		}
	}
}

func (t *tt) read(
	ctx context.Context,
	log *zap.Logger,
	recvCh chan<- llap.Packet,
) {
	defer close(recvCh)
	go func() {
		<-ctx.Done()
		t.port.Close()
	}()

	for {
		packet := llap.Packet{}
		err := t.dec.Decode(&packet)
		if err == io.EOF {
			return
		} else if err != nil {
			log.With(zap.Error(err)).Error("read failed")
			continue
		}
		recvCh <- packet
	}
}
