/*
 * Copyright (c) 2009 Rob Braun <bbraun@synack.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Rob Braun nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <stdint.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#define MAX_SOCKS 5
#define VERSION "abridge 0.1"

#ifdef DEBUG
#define DebugLog(format, ...) printf(format, __VA_ARGS__)
#else
#define DebugLog(...)
#endif

void print_buffer(unsigned char *buffer, size_t len) {
#ifdef DEBUG
        size_t i;
        for(i = 0; i < len; i++) {
                printf("%.2x", buffer[i]);
        }
        printf("\n");
#endif
}


int handle_receive(int infd, int *sockets, int inuse, int inuse_bitmap) {
	ssize_t r;
	uint32_t len = 0;
	unsigned char *buffer = NULL;
	size_t numread = 0;
	size_t numwrote = 0;

	DebugLog("Handling a recieved frame\n%s", "");

	// First read the frame length
	buffer = (unsigned char *)&len;
	do {
		r = read(infd, buffer + numread, 4 - numread);
		if( (r == -1) && (errno == EINTR) )
			continue;
		if( r <= 0 ) {
			perror("read");
			close(infd);
			return -1;
		}
		numread += r;
	} while ( numread < 4 );

	len = ntohl(len);
	// Sanity check;
	if( len > 4096 ) {
		return -2;
	}

	DebugLog("Frame length: %u\n", len);
	// Allocate enough space for the subsequent frame
	buffer = calloc(1, len);
	if( !buffer )
		return -3;

	// Read frame
	numread = 0;
	do {
		r = read(infd, buffer + numread, len - numread);
		if( (r == -1) && (errno == EINTR) )
			continue;
		if( r <= 0 ) {
			perror("read");
			return -1;
		}
		numread += r;
	} while ( numread < len );

	print_buffer(buffer, len);
	
	// Now we have the frame, we need to write it to each of the clients
	int i;
	for(i = 0; i < MAX_SOCKS; i++) {
		// Don't write to the socket this came from
		if( sockets[i] == infd )
			continue;

		// If this slot isn't used, skip it
		if( !(inuse_bitmap & (1<<i)) )
			continue;
		DebugLog("Attempting to write out frame to descriptor %d\n", sockets[i]);

		// Write frame length
		numwrote = 0;
		uint32_t networklen = htonl(len);
		char *tmpbuf = (char *)&networklen;
		int failed = 0;
		do {
			r = write(sockets[i], tmpbuf + numwrote, 4 - numwrote);
			if( (r == -1) && (errno == EINTR) ) {
				continue;
			}
			if( r <= 0 ) {
				// skip the rest of this client.
				failed = 1;
				break;
			}
			numwrote += r;
		}while(numwrote < 4);

		// If the write of the length failed, skip this client 
		// and continue servicing the rest.
		if( failed ) {
			DebugLog("Failed to write out packet length to descriptor %d\n", sockets[i]);
			free(buffer);
			continue;
		}

		numwrote = 0;
		do {
			r = write(sockets[i], buffer + numwrote, len - numwrote);
			if( (r == -1) && (errno == EINTR) ) {
				continue;
			}
			if( r <= 0 ) {
				break;
			}
			numwrote += r;
		}while(numwrote < len);
		DebugLog("Successfully wrote out packet to descriptor %d\n", sockets[i]);
		print_buffer(buffer, len);
	}

	free(buffer);

	return 0;
}

void usage(char *progname) {
	fprintf(stderr, "Usage: %s [-h] [-d] [-p portnum]\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "-d | --dontfork    Do not daemonize\n");
	fprintf(stderr, "-p | --port #      Specify port number to listen on\n");
	fprintf(stderr, "-v | --version     Display version & exit\n");
	fprintf(stderr, "-h | --help        This message\n");
	return;
}

int main(int argc, char *argv[]) {
	int listenfd;
	uint16_t portnum = 9999;
	struct sockaddr_in serveraddr;
	int sockets[MAX_SOCKS];
	int inuse_bitmap = 0;
	int inuse = 0;
	pid_t pid;
	struct option o[] = {
		{"dontfork", no_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{"port", required_argument, 0, 'p'},
		{"version", no_argument, 0, 'v'},
		{0, 0, 0, 0}
	};
	char c;
	int dontfork = 0;
	char *portstr = "9999";

	while( (c = getopt_long(argc, argv, "dhp:v", o, 0)) != (char)-1) {
		switch(c) {
		case 'd':
			dontfork = 1;
			break;
		case 'p':
			if( !optarg ) {
				usage(argv[0]);
				exit(1);
			}
			portstr = optarg;
			break;
		case 'v':
			printf("%s\n", VERSION);
			exit(0);
		case 'h':
			usage(argv[0]);
			exit(0);
		}
	}

	// Convert port number string to a valid port
	long tmpnum;
	errno = 0;
	tmpnum = strtol(portstr, NULL, 10);
	if( (((tmpnum == LONG_MIN) || (tmpnum == LONG_MAX)) && (errno == ERANGE)) || (errno == EINVAL) ) {
		fprintf(stderr, "Invalid port number: %s\n", portstr);
		exit(3);
	}
	if( (tmpnum < 1) || (tmpnum > 0xFFFF) ) {
		fprintf(stderr, "Port number %s out of range: %ld\n", portstr, tmpnum);
		exit(4);
	}
	portnum = tmpnum;

	// Daemonize
	if( !dontfork ) {
		pid = fork();
		if( pid == -1 ) {
			perror("fork");
			exit(1);
		}
		if( pid > 0 )
			exit(0);
		setsid();
	}
	
	// Setup listening socket
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(portnum);
	serveraddr.sin_addr.s_addr = INADDR_ANY;
	
	listenfd = socket(PF_INET, SOCK_STREAM, 0);
	if( listenfd < 0 ) {
		perror("socket");
		exit(1);
	}

	int on = 1;
	setsockopt( listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, (socklen_t)sizeof(on));

	if( bind(listenfd, (struct sockaddr *)&serveraddr, (socklen_t)sizeof(serveraddr)) != 0) {
		perror("bind");
		exit(2);
	}

	if( listen(listenfd, 5) != 0 ) {
		perror("listen");
		exit(3);
	}

	fd_set master_readset;
	int nactive = listenfd+1;

	FD_ZERO(&master_readset);
	FD_SET(listenfd, &master_readset);

	while(1) {
		int selret;
		fd_set readset = master_readset;

		errno = 0;
		selret = select(nactive, &readset, NULL, NULL, NULL);
		if( selret == -1 ) {
			if( errno == EINTR )
				continue;
			if( errno == EBADF ) {
				int fd;
				struct stat st;

				for(fd = 0; fd < nactive; fd++) {
					if( FD_ISSET(fd, &master_readset) &&
					    (fstat(fd, &st) == -1) ) {
						FD_CLR(fd, &master_readset);
						int i;
						for(i = 0; i < MAX_SOCKS; i++) {
							if( sockets[i] == fd ) {
								inuse_bitmap &= ~(1<<i);
								inuse--;
								break;
							}
						}
						break;
					}
				}
			}
		} else {
			int i;

			if( FD_ISSET(listenfd, &readset) ) {
				int clientfd;

				clientfd = accept(listenfd, NULL, NULL);
				if( clientfd < 0 ) {
					perror("accept");
					return -1;
				}
				DebugLog("Accepted client: %d (%d active)\n", clientfd, inuse);

				if( inuse >= MAX_SOCKS ) {
					close(clientfd);
				} else {
					int i;
					for(i = 0; i < MAX_SOCKS; i++) {
						if( !(inuse_bitmap & (1<<i)) ) {
							sockets[i] = clientfd;
							inuse_bitmap |= (1<<i);
							FD_SET(clientfd, &master_readset);
							inuse++;
							nactive = (nactive > clientfd) ? nactive : clientfd+1;
							DebugLog("Added descriptor %d to read set (%d active)\n", clientfd, inuse);
							break;
						}
					}
				}

				selret--;
			}

			if( selret == 0 )
				continue;

			for(i = 0; i < MAX_SOCKS; i++) {
				if( (inuse_bitmap & (1<<i)) && 
				    FD_ISSET(sockets[i], &readset) ) {
					handle_receive(sockets[i], sockets, inuse, inuse_bitmap);
					selret--;
				}
				if( selret == 0 )
					break;
			}
		}
	}
}
