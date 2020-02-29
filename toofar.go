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
// void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
//     struct capture_context *cctx = (struct capture_context*)args;
//     int serverfd = cctx->fd;
//     uint32_t len = htonl(header->caplen);
//
//     DebugLog("packet_handler entered%s", "\n");
//
//     // Check to make sure the packet we just received wasn't sent
//     // by us (the bridge), otherwise this is how loops happen
//     pthread_mutex_lock(&qumu);
//     struct packet *np;
//     for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) {
//         if( np->len == header->caplen ) {
//             if( memcmp(packet, np->buffer, header->caplen) == 0 ) {
//                 free(np->buffer);
//                 TAILQ_REMOVE(&head, np, entries);
//                 free(np);
//                 pthread_mutex_unlock(&qumu);
//                 DebugLog("packet_handler returned, skipping our own packet%s", "\n");
//                 return;
//             }
//         }
//     }
//     pthread_mutex_unlock(&qumu);
//
//     // anything less than this isn't a valid frame
//     if( header->caplen < 18 ) {
//         DebugLog("packet_handler returned, skipping invalid packet%s", "\n");
//         return;
//     }
//
//     // Check to see if the destination address matches any addresses
//     // in the list of source addresses we've seen on our network.
//     // If it is, don't bother sending it over the bridge as the
//     // recipient is local.
//     struct addrlist *ap;
//     struct addrlist *srcaddrmatch = NULL;
//     for (ap = cctx->addrhead.tqh_first; ap != NULL; ap = ap->entries.tqe_next) {
//         if( memcmp(packet, ap->srcaddr, 6) == 0 ) {
//             DebugLog("packet_handler returned, skipping local packet%s", "\n");
//             return;
//         }
//         // Since we're going through the list anyway, see if
//         // the source address we've observed is already in the
//         // list, in case we want to add it.
//         if( memcmp(packet+6, ap->srcaddr, 6) == 0 ) {
//             srcaddrmatch = ap;
//         }
//     }
//
//     // Destination is remote, but originated locally, so we can add
//     // the source address to our list.
//     if( !srcaddrmatch ) {
//         struct addrlist *newaddr = calloc(1,sizeof(struct addrlist));
//         memcpy(newaddr->srcaddr, packet+6, 6);
//         TAILQ_INSERT_TAIL(&cctx->addrhead, newaddr, entries);
//     }
//
//     if( header->caplen != header->len ) {
//         DebugLog("truncated packet! %s\n", "");
//     }
//     write(serverfd, &len, sizeof(len));
//     write(serverfd, packet, header->caplen);
//     DebugLog("Wrote packet of size %d\n", header->caplen);
//     return;
// }
//
// void capture(char *dev, int serverfd) {
//     char errbuf[PCAP_ERRBUF_SIZE];
//     struct capture_context cctx;
//
//     cctx.fd = serverfd;
//     TAILQ_INIT(&cctx.addrhead);
//
//     DebugLog("Using device: %s\n", dev);
//     pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
//     if( !handle ) {
//         fprintf(stderr, "Couldn't open pcap for device %s: %s\n", dev, errbuf);
//         exit(3);
//     }
//
//     char filter[] = "atalk or aarp";
//     struct bpf_program fp;
//     bpf_u_int32 net;
//     if( pcap_compile(handle, &fp, filter, 0, net) == -1 ) {
//         fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
//         exit(4);
//     }
//
//     if( pcap_setfilter(handle, &fp) == -1 ) {
//         fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
//         exit(5);
//     }
//
//     pcap_loop(handle, -1, packet_handler, (u_char*)&cctx);
// }
//
// void transmit(char *dev, int serverfd) {
//     char errbuf[PCAP_ERRBUF_SIZE];
//
//     DebugLog("Using device: %s\n", dev);
//     pcap_t *handle = pcap_open_live(dev, 1, 0, 1000, errbuf);
//     if( !handle ) {
//         fprintf(stderr, "Couldn't open pcap for device %s: %s\n", dev, errbuf);
//         exit(3);
//     }
//
//     fd_set master_readset;
//     int nactive = serverfd+1;
//
//     FD_ZERO(&master_readset);
//     FD_SET(serverfd, &master_readset);
//     while(1) {
//         int selret;
//         fd_set readset = master_readset;
//
//         errno = 0;
//         selret = select(nactive, &readset, NULL, NULL, NULL);
//         DebugLog("select woke up: %d\n", selret);
//         if( selret == -1 ) {
//             if( errno == EINTR )
//                 continue;
//             fprintf(stderr, "problem with select\n");
//             break;
//         }
//         if( selret == 0 )
//             continue;
//
//         // receive a frame and send it out on the net
//         uint32_t len = 0;
//         uint32_t tmplen = 0;
//         uint8_t *buffer = (uint8_t *)&tmplen;
//         size_t numread = 0;
//         ssize_t r;
//
//         do {
//             r = read(serverfd, buffer + numread, 4 - numread);
//             if( (r == -1) && (errno == EINTR) )
//                 continue;
//             if( r <= 0 ) {
//                 perror("read");
//                 exit(1);
//                 buffer = NULL;
//                 goto playitagain;
//             }
//             numread += r;
//         } while( numread < 4 );
//
//         len = ntohl(tmplen);
//         if( len > 4096 ) {
//             fprintf(stderr, "Received length is invalid: %" PRIu32 " vs %" PRIu32 "\n", len, tmplen);
//             continue;
//         }
//         DebugLog("receiving packet of length: %u\n", len);
//
//         buffer = calloc(1, len);
//         if( !buffer )
//             exit(99);
//
//         numread = 0;
//         do {
//             r = read(serverfd, buffer + numread, len - numread);
//             if( (r == -1) && (errno == EINTR) )
//                 continue;
//             if( r <= 0 ) {
//                 perror("read");
//                 exit(1);
//                 goto playitagain;
//             }
//             numread += r;
//         } while( numread < len );
//         DebugLog("Successfully received packet\n%s", "");
//
//         print_buffer(buffer, len);
//
//         /* 6 + 6 + 2 + 1 + 1 + 1 + 3 +2<type> + 4crc*/
//         if( len < 26 ) {
//             // Too short to be a valid ethernet frame
//             goto playitagain;
//         }
//
//         // Verify this is actuall an AppleTalk related frame we've
//         // received, in a vague attempt at not polluting the network
//         // with unintended frames.
//         uint16_t type = htons(*(uint16_t*)(buffer+20));
//         DebugLog("Packet frame type: %x\n", type);
//         if( ! ((type == 0x809b) || (type == 0x80f3)) ) {
//             // Not an appletalk or aarp frame, drop it.
//             DebugLog("Not an AppleTalk or AARP frame, dropping: %d\n", type);
//             goto playitagain;
//         }
//
//         // We now have a frame, time to send it out.
//         struct packet *lastsent = calloc(1,sizeof(struct packet));
//         lastsent->buffer = buffer;
//         lastsent->len = len;
//
//         pthread_mutex_lock(&qumu);
//         TAILQ_INSERT_TAIL(&head, lastsent, entries);
//         pthread_mutex_unlock(&qumu);
//         int pret = pcap_sendpacket(handle, buffer, len);
//         DebugLog("pcap_sendpacket returned %d\n", pret);
//         if( pret != 0 ) {
//             fprintf(stderr, "Error sending packet out onto local net\n");
//         }
//         // The capture thread will free these
//         buffer = NULL;
// playitagain:
//         if( buffer ) free(buffer);
//
//     }
// }
//
// void head_tailq_init() {
//     TAILQ_INIT(&head);
// }
import "C"
import (
	"fmt"
	"os"

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
		C.capture(C.CString(*dev), socket)
	}()
	go func() {
		C.transmit(C.CString(*dev), socket)
	}()
	<-ch
}

func initialize() (socket C.int) {
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
	return serverfd
}
