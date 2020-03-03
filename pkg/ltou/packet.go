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
package ltou

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
)

const (
	LLAPDDP    = LLAPType(0x01)
	LLAPExtDDP = LLAPType(0x02)
	LLAPEnq    = LLAPType(0x81)
	LLAPAck    = LLAPType(0x82)
)

var (
	MulticastAddr = &net.UDPAddr{
		IP:   net.IPv4(239, 192, 76, 84),
		Port: 1954,
	}
)

type (
	LLAPType uint8

	Header struct {
		Pid              uint32
		DstNode, SrcNode uint8
		Kind             LLAPType
	}
	Packet struct {
		Header
		Data []byte
	}
)

func Unmarshal(data []byte, pak *Packet) error {
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.BigEndian, &pak.Header)
	if err != nil {
		return fmt.Errorf("read udp header: %s", err.Error())
	}

	pak.Data, err = ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read udp body: %s", err.Error())
	}

	return nil
}

func Marshal(pak Packet) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})

	err := binary.Write(buf, binary.BigEndian, pak.Header)
	if err != nil {
		return nil, fmt.Errorf("write udp header: %s", err.Error())
	}

	n, err := buf.Write(pak.Data)
	if err != nil {
		return nil, fmt.Errorf("write udp body: %s", err.Error())
	} else if n < len(pak.Data) {
		return nil, fmt.Errorf("write udp body: incomplete write (%d < %d)", n, len(pak.Data))
	}

	return buf.Bytes(), nil
}
