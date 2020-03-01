package ethertalk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/sfiera/multitalk/pkg/ethertalk"
)

const (
	Ethernet     = uint16(0x0001)
	LLAPBridging = uint16(0x809b)

	RequestOp  = uint16(0x01)
	ResponseOp = uint16(0x02)
	ProbeOp    = uint16(0x03)
)

var (
	EthernetLLAPBridging = Header{
		Hardware:     Ethernet,
		Proto:        LLAPBridging,
		HardwareSize: 6,
		ProtoSize:    4,
	}
)

type (
	AtalkAddr struct {
		_       uint8
		Network uint16
		Node    uint8
	}

	Header struct {
		Hardware, Proto         uint16
		HardwareSize, ProtoSize uint8
	}
	AddrPair struct {
		Hardware ethertalk.EthAddr
		Proto    AtalkAddr
	}
	Body struct {
		Opcode uint16
		Src    AddrPair
		Dst    AddrPair
	}
	Packet struct {
		Header
		Body
	}
)

// Unmarshals a packet from bytes.
func Unmarshal(data []byte, pak *Packet) error {
	r := bytes.NewReader(data)

	err := binary.Read(r, binary.BigEndian, &pak.Header)
	if err != nil {
		return fmt.Errorf("read aarp header: %s", err.Error())
	} else if pak.Header != EthernetLLAPBridging {
		return fmt.Errorf("read aarp header: not eth-llap bridging")
	}

	err = binary.Read(r, binary.BigEndian, &pak.Body)
	if err != nil {
		return fmt.Errorf("read aarp body: %s", err.Error())
	}

	_, err = r.ReadByte()
	if err != io.EOF {
		return fmt.Errorf("read aarp: excess data")
	}

	return nil
}

// Marshals a packet to bytes.
func Marshal(pak Packet) ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 28))
	err := binary.Write(w, binary.BigEndian, pak)
	if err != nil {
		return nil, fmt.Errorf("write aarp: %s", err.Error())
	}

	return w.Bytes(), nil
}

// AARP packet for resolving `query` to a hardware address, from `src`.
func Request(src AddrPair, query AtalkAddr) Packet {
	return Packet{
		Header: EthernetLLAPBridging,
		Body: Body{
			Opcode: RequestOp,
			Src:    src,
			Dst:    AddrPair{Proto: query},
		},
	}
}

// AARP packet responding to a request or probe `dst` from `src.
func Response(src, dst AddrPair) Packet {
	return Packet{
		Header: EthernetLLAPBridging,
		Body: Body{
			Opcode: ResponseOp,
			Src:    src,
			Dst:    dst,
		},
	}
}

// AARP packet for checking that `query` is available, from `src`.
func Probe(src ethertalk.EthAddr, query AtalkAddr) Packet {
	return Packet{
		Header: EthernetLLAPBridging,
		Body: Body{
			Opcode: ProbeOp,
			Src: AddrPair{
				Hardware: src,
				Proto:    query,
			},
			Dst: AddrPair{Proto: query},
		},
	}
}
