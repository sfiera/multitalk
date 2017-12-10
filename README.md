# Introduction

abridge is an EtherTalk bridge, or rather a really dumb repeater.

It essentially takes EtherTalk frames off the specified interface, wraps them in TCP, and sends them to a server process.  Multiple clients can then connect to this server, and all EtherTalk frames from all clients will be sent to all the other clients.

The purpose of this is to be able to play old AppleTalk only games over the internet with other fans of such old and obsolete things.

Here's the bad part(s), this allows anyone to send anything at all onto your network.  There is no authentication, encryption, or access controls are used.  Basically, if you connect to the server, anyone else connected to that server can stuff things onto your network.  BEWARE!  There is some basic checking in the bridge portion to ensure only AppleTalk and AppleTalk Address Resolution Protocol frames are put on the network.

The server itself should only interact with clients, so running that on a network without AppleTalk is fine.

## Prerequisites

On ubuntu, you need libpcap which can be installed by running:

`sudo apt-get install libpcap-dev`

# Usage

If that didn't scare you away, here's how to run it.

There are two processes:

`toofar`: the bridge.  This takes packets from the local network and sends them to the server, which sends them to the other connected bridges.

`kwai`: the server.  This is what the bridges connect to.

Here is the example use:

On a machine accessible from all the desired bridges:

`./kwai [-d] [-p port#]`

On each bridge:

`./toofar [-i interface] [-s server] [-p port]`

## Troubleshooting:

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

Rob Braun [<bbraun@synack.net>](mailto:bbraun@synack.net)
