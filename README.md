# Introduction

MultiTalk is a repeater for different transports for AppleTalk:
* EtherTalk, spoken by Classic MacOS or netatalk2 machines over Ethernet
* LocalTalk-over-UDP (LToU) multicast, spoken by Mini vMac 37+
* TCP, spoken by the `kwai` component of bbraun’s abridge

[![Build Status](https://cloud.drone.io/api/badges/sfiera/multitalk/status.svg)](https://cloud.drone.io/sfiera/multitalk) [![Godoc](https://godoc.org/github.com/sfiera/multitalk/pkg?status.svg)](https://godoc.org/github.com/sfiera/multitalk/pkg)

# Usage

Convert between EtherTalk and LToU on the ethernet port:

    sudo multitalk --ethertalk eth0 --multicast eth0

The same, except printing all packets for debugging:

    sudo multitalk -e eth0 -m eth0 --debug

# Credits

See [AUTHORS](AUTHORS). Notable contributions:

* Original abridge code by Rob Braun <bbraun@synack.net>
* Conversion to MultiTalk by Chris Pickel [@sfiera](https://github.com/sfiera)
* LToU specification by Rob Mitchelmore [@cheesestraws](https://github.com/cheesestraws)
