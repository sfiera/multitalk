# Introduction

abridge is an EtherTalk bridge, or rather a really dumb repeater.

It essentially takes EtherTalk frames off the specified interface, wraps them in TCP, and sends them to a server process.  Multiple clients can then connect to this server, and all EtherTalk frames from all clients will be sent to all the other clients.

The purpose of this is to be able to play old AppleTalk only games over the internet with other fans of such old and obsolete things.

Here's the bad part(s), this allows anyone to send anything at all onto your network.  There is no authentication, encryption, or access controls are used.  Basically, if you connect to the server, anyone else connected to that server can stuff things onto your network.  BEWARE!  There is some basic checking in the bridge portion to ensure only AppleTalk and AppleTalk Address Resolution Protocol frames are put on the network.

The server itself should only interact with clients, so running that on a network without AppleTalk is fine.

## Prerequisites

On ubuntu, you need libpcap which can be installed by running:

	sudo apt-get install libpcap-dev

# Usage

If that didn't scare you away, here's how to run it.

There are two processes:

`toofar`: the bridge.  This takes packets from the local network and sends them to the server, which sends them to the other connected bridges.

`kwai`: the server.  This is what the bridges connect to.

Here is the example use:

On a machine accessible from all the desired bridges:

	./kwai [-d] [-p port#]

On each bridge:

	./toofar [-i interface] [-s server] [-p port]

## Notes

The server has been tested to run on Ubuntu Linux and Mac OS X.  The bridges are only tested on Ubuntu, but theoretically should work anywhere libpcap supports packet injection.

The bridge must be run on a machine that does not need to be remotely accessible via EtherTalk.  When it injects a packet onto the local network, local processes such a netatalk will not see the injected packets.  That means machines on the other side of other bridges will not see the services of the machine the local bridge is running on.  Bridges are somewhat "invisible" on the network.

This uses libpcap to do the packet capture and injection.  pcap includes the following warning about problems with various network drivers and injecting packets:

> Note  that,  on  some  platforms,  the  link-layer header of the packet
> that's sent might not be the same  as  the  link-layer  header  of  the
> packet  supplied to pcap_inject(), as the source link-layer address, if
> the header contains such an address, might be changed to be the address
> assigned  to the interface on which the packet it sent, if the platform
> doesn't support sending completely raw  and  unchanged  packets.   Even
> worse,  some drivers on some platforms might change the link-layer type
> field to whatever value libpcap used when attaching to the device, even
> on  platforms  that  do  nominally  support  sending completely raw and
> unchanged packets.

## Troubleshooting

The first thing to do when troubleshooting is build both client and server with debugging enabled and run them in the foreground:

	make clean; make CFLAGS="-DDEBUG=1"
	./kwai -d
	sudo ./toofar -d -i eth0 -s servername

Next, if you have another machine on the network with netatalk installed (remember, you can't run this on a machine the client is running on), run `nbplkup`. This should show the machines visible on the network:

	bbraun@bbraun-desktop:~/abridge$ nbplkup
	                 bbraun-desktop:AFPServer                          65280.34:128
	                 bbraun-desktop:netatalk                           65280.34:4
	                 bbraun-desktop:Workstation                        65280.34:4
	                         server:ProDOS16 Image                     65280.1:236
	                         server:Apple //gs                         65280.1:236
	                         server:Apple //e Boot                     65280.1:236
	                         server:AFPServer                          65280.1:251
	                         server:  Macintosh                        65280.1:252
	                         server:Workstation                        65280.1:4

And finally, tcpdump or ethereal to log/inspect the network can be helpful. 

When reporting a problem, the debug output of both the server and client (or only client if you're connecting to a server you can't get the output of) and a tcpdump capture file of the problem:

	tcpdump -n -i eth0 -s0 -w outfile atalk or aarp

Running tcpdump on the same host as the client is ok.

If you run it on a wireless interface on ubuntu or a Raspberry Pi, you need to set it into `monitor` mode ([more info](https://sandilands.info/sgordon/capturing-wifi-in-monitor-mode-with-iw)):

	$ iw dev
	phy#0
	Interface wlan0
		ifindex 3
		type managed
	$ sudo iw phy phyN interface add mon0 type monitor

where `phyN` is the `phy` your `wlan0` interface is on.  In the example, `phy#0` should be entered as `phy0`.

If your wireless interface doesn't support monitoring, you'll see something like:

	sudo iw phy phy0 interface add mon0 type monitor
	command failed: Operation not supported (-95)

--
Rob Braun [<bbraun@synack.net>](mailto:bbraun@synack.net)
