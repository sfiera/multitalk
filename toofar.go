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

// #cgo LDFLAGS: -lpcap
// #include <stdlib.h>
// #include <stdio.h>
// #include <pcap.h>
// #include <getopt.h>
// #include <sys/types.h>
// #include <pthread.h>
// #include <sys/socket.h>
// #include <inttypes.h>
// #include <stdint.h>
// #include <netdb.h>
// #include <string.h>
// #include <errno.h>
// #include <unistd.h>
// #include <sys/queue.h>
//
// #define VERSION "abridge 0.1"
//
// #ifdef DEBUG
// #define DebugLog(format, ...) printf(format, __VA_ARGS__)
// #else
// #define DebugLog(...)
// #endif
//
// pthread_mutex_t qumu;
// TAILQ_HEAD(lastq, packet) head;
// struct packet {
//     uint8_t *buffer;
//     size_t len;
//     TAILQ_ENTRY(packet) entries;
// };
//
// struct addrlist {
//     uint8_t srcaddr[6];
//     TAILQ_ENTRY(addrlist) entries;
// };
//
// struct capture_context {
//     int fd;
//     TAILQ_HEAD(addrq, addrlist) addrhead;
// };
//
// struct etherhdr {
//     uint8_t dst[6];
//     uint8_t src[6];
//     uint16_t type;
// };
//
// void print_buffer(uint8_t *buffer, size_t len) {
// #ifdef DEBUG
//     size_t i;
//     for(i = 0; i < len; i++) {
//         printf("%.2x", buffer[i]);
//     }
//     printf("\n");
// #endif
// }
//
// void init_cctx(struct capture_context *cctx, int fd) {
//     cctx->fd = fd;
//     TAILQ_INIT(&cctx->addrhead);
// }
//
// void tailq_remove_packet(struct packet *np) {
//     TAILQ_REMOVE(&head, np, entries);
// }
//
// void tailq_insert_addr(struct capture_context *cctx, struct addrlist *newaddr) {
//     TAILQ_INSERT_TAIL(&cctx->addrhead, newaddr, entries);
// }
//
// void tailq_insert_packet(struct packet *np) {
//     pthread_mutex_lock(&qumu);
//     TAILQ_INSERT_TAIL(&head, np, entries);
//     pthread_mutex_unlock(&qumu);
// }
//
// void head_tailq_init() {
//     TAILQ_INIT(&head);
// }
//
// uint16_t frame_type(const uint8_t *packet) {
//     return htons(*(uint16_t*)(packet + 20));
// }
import "C"
import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/google/gopacket/pcap"
	"github.com/spf13/pflag"
)

var (
	dev     = pflag.StringP("interface", "i", "", "Specify the interface to bridge to")
	server  = pflag.StringP("server", "s", "127.0.0.1", "Specify the server to connect to")
	port    = pflag.StringP("port", "p", "9999", "Specify the port number to connect to")
	version = pflag.BoolP("version", "v", false, "Display version & exit")
)

func main() {
	pflag.Parse()

	if *version {
		fmt.Println(C.VERSION)
		os.Exit(0)
	} else if *dev == "" {
		fmt.Fprintf(os.Stderr, "%s: missing required flag --interface\n", os.Args[0])
		os.Exit(1)
	}

	ch := make(chan bool)
	socket := initialize()
	go func() {
		defer close(ch)
		capture(socket)
	}()
	go func() {
		transmit(socket)
	}()
	<-ch
}

func initialize() (socket int) {
	hints := C.struct_addrinfo{
		ai_family:   C.PF_INET,
		ai_socktype: C.SOCK_STREAM,
		ai_protocol: C.IPPROTO_TCP,
	}
	res := (*C.struct_addrinfo)(nil)

	if C.getaddrinfo(C.CString(*server), C.CString(*port), &hints, &res) != 0 {
		fmt.Fprintf(os.Stderr, "Unknown hostname: %s\n", server)
		os.Exit(5)
	}

	serverfd := C.socket(C.PF_INET, C.SOCK_STREAM, 0)
	if serverfd < 0 {
		fmt.Fprintf(os.Stderr, "socket call failed\n")
		os.Exit(6)
	}

	if C.connect(serverfd, res.ai_addr, (C.socklen_t)(C.sizeof_struct_sockaddr_in)) != 0 {
		fmt.Fprintf(os.Stderr, "connect failed\n")
		os.Exit(7)
	}

	C.pthread_mutex_init(&C.qumu, nil)
	C.head_tailq_init()
	return int(serverfd)
}

func capture(serverfd int) {
	cctx := C.struct_capture_context{}

	C.init_cctx(&cctx, C.int(serverfd))

	// DebugLog("Using device: %s\n", dev)
	handle, err := pcap.OpenLive(*dev, 4096, true, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open dev %s: %s\n", *dev, err.Error())
		os.Exit(3)
	}

	filter := "atalk or aarp"
	fp, err := handle.CompileBPFFilter(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile filter %s: %s\n", filter, err.Error())
		os.Exit(4)
	}

	err = handle.SetBPFInstructionFilter(fp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "install filter %s: %s\n", filter, err.Error())
		os.Exit(5)
	}

	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			fmt.Fprintf(os.Stderr, "read packet %s: %s\n", *dev, err.Error())
			os.Exit(5)
		}
		if ci.CaptureLength != ci.Length {
			// DebugLog("truncated packet! %s\n", "");
		}
		packet_handler(&cctx, ci.CaptureLength, data)
	}
}

func packet_handler(cctx *C.struct_capture_context, len int, packet []byte) {
	serverfd := cctx.fd

	// DebugLog("packet_handler entered%s", "\n")

	// Check to make sure the packet we just received wasn't sent
	// by us (the bridge), otherwise this is how loops happen
	C.pthread_mutex_lock(&C.qumu)
	for np := C.head.tqh_first; np != nil; np = np.entries.tqe_next {
		if int(np.len) == len {
			if C.memcmp(unsafe.Pointer(&packet[0]), unsafe.Pointer(np.buffer), C.size_t(len)) == 0 {
				C.free(unsafe.Pointer(np.buffer))
				C.tailq_remove_packet(np)
				C.free(unsafe.Pointer(np))
				C.pthread_mutex_unlock(&C.qumu)
				// DebugLog("packet_handler returned, skipping our own packet%s", "\n")
				return
			}
		}
	}
	C.pthread_mutex_unlock(&C.qumu)

	// anything less than this isn't a valid frame
	if len < 18 {
		// DebugLog("packet_handler returned, skipping invalid packet%s", "\n")
		return
	}

	// Check to see if the destination address matches any addresses
	// in the list of source addresses we've seen on our network.
	// If it is, don't bother sending it over the bridge as the
	// recipient is local.
	srcaddrmatch := (*C.struct_addrlist)(nil)
	for ap := cctx.addrhead.tqh_first; ap != nil; ap = ap.entries.tqe_next {
		if C.memcmp(unsafe.Pointer(&packet[0]), unsafe.Pointer(&ap.srcaddr[0]), 6) == 0 {
			// DebugLog("packet_handler returned, skipping local packet%s", "\n")
			return
		}
		// Since we're going through the list anyway, see if
		// the source address we've observed is already in the
		// list, in case we want to add it.
		if C.memcmp(unsafe.Pointer(&packet[6]), unsafe.Pointer(&ap.srcaddr[0]), 6) == 0 {
			srcaddrmatch = ap
		}
	}

	// Destination is remote, but originated locally, so we can add
	// the source address to our list.
	if srcaddrmatch == nil {
		newaddr := (*C.struct_addrlist)(C.calloc(1, C.sizeof_struct_addrlist))
		C.memcpy(unsafe.Pointer(&newaddr.srcaddr[0]), unsafe.Pointer(&packet[6]), 6)
		C.tailq_insert_addr(cctx, newaddr)
	}

	netlen := [4]byte{}
	binary.BigEndian.PutUint32(netlen[:], uint32(len))
	C.write(serverfd, unsafe.Pointer(&netlen[0]), 4)
	C.write(serverfd, unsafe.Pointer(&packet[0]), C.size_t(len))
	// DebugLog("Wrote packet of size %d\n", len)
}

func transmit(serverfd int) {
	//char errbuf[PCAP_ERRBUF_SIZE];

	// DebugLog("Using device: %s\n", dev);
	handle, err := pcap.OpenLive(*dev, 1, false, 1000)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open dev %s: %s\n", *dev, err.Error())
		os.Exit(3)
	}

	for {
		// receive a frame and send it out on the net
		len := uint32(0)
		numread := uint32(0)
		lenBuf := [4]byte{}

		for loop := true; loop; loop = numread < 4 {
			r, err := C.read(C.int(serverfd), unsafe.Pointer(&lenBuf[numread]), C.size_t(4-numread))
			if (r == -1) && (err == syscall.EINTR) {
				continue
			}
			if r <= 0 {
				C.perror(C.CString("read"))
				os.Exit(1)
				continue
			}
			numread += uint32(r)
		}

		len = binary.BigEndian.Uint32(lenBuf[:])
		if len > 4096 {
			fmt.Fprintf(os.Stderr, "Received length is invalid: %u vs %u\n", len)
			continue
		}
		// DebugLog("receiving packet of length: %u\n", len);

		packetBuf := (*C.uint8_t)(C.calloc(1, C.size_t(len)))
		if packetBuf == nil {
			os.Exit(99)
		}

		numread = 0
		for loop := true; loop; loop = numread < len {
			r, err := C.read(C.int(serverfd), unsafe.Pointer(packetBuf), C.size_t(len-numread))
			if (r == -1) && (err == syscall.EINTR) {
				continue
			}
			if r <= 0 {
				C.perror(C.CString("read"))
				os.Exit(1)
				if packetBuf != nil {
					C.free(unsafe.Pointer(packetBuf))
				}
				continue
			}
			numread += uint32(r)
		}
		// DebugLog("Successfully received packet\n%s", "");

		C.print_buffer(packetBuf, C.size_t(len))

		/* 6 + 6 + 2 + 1 + 1 + 1 + 3 +2<type> + 4crc*/
		if len < 26 {
			// Too short to be a valid ethernet frame
			if packetBuf != nil {
				C.free(unsafe.Pointer(packetBuf))
			}
			continue
		}

		// Verify this is actuall an AppleTalk related frame we've
		// received, in a vague attempt at not polluting the network
		// with unintended frames.
		frameType := C.frame_type(packetBuf)
		// DebugLog("Packet frame type: %x\n", type);
		if !((frameType == 0x809b) || (frameType == 0x80f3)) {
			// Not an appletalk or aarp frame, drop it.
			// DebugLog("Not an AppleTalk or AARP frame, dropping: %d\n", frameType);
			if packetBuf != nil {
				C.free(unsafe.Pointer(packetBuf))
			}
			continue
		}

		// We now have a frame, time to send it out.
		lastsent := (*C.struct_packet)(C.calloc(1, C.sizeof_struct_packet))
		lastsent.buffer = packetBuf
		lastsent.len = C.size_t(len)
		C.tailq_insert_packet(lastsent)

		err := handle.WritePacketData(C.GoBytes(unsafe.Pointer(packetBuf), C.int(len)))
		// DebugLog("pcap_sendpacket returned %d\n", pret);
		if err != nil {
			fmt.Fprintf(os.Stderr, "write packet: %s\n", err.Error())
		}
		// The capture thread will free these
	}
}
