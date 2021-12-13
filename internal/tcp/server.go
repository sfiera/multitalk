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
	"fmt"
	"net"

	"go.uber.org/zap"

	"github.com/sfiera/multitalk/internal/bridge"
)

type server struct {
	listen net.Listener
}

func TCPServer(listen string) (*server, error) {
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %s", listen, err.Error())
	}
	return &server{l}, nil
}

func (s *server) Serve(ctx context.Context, log *zap.Logger, grp *bridge.Group) {
	go func() {
		for {
			c, err := s.listen.Accept()
			if err != nil {
				continue
			}
			log.With(
				zap.String("bridge", "tcp"),
				zap.Stringer("remoteAddr", c.RemoteAddr()),
			).Info("opened")
			grp.Add((&client{c}).Start(ctx, log))
		}
	}()
}
