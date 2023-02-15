# Introduction

MultiTalk is a repeater for different transports for AppleTalk:
* EtherTalk, spoken by Classic MacOS or netatalk2 machines over Ethernet
* LocalTalk-over-UDP (LToU) multicast, spoken by Mini vMac 37+
* TCP, spoken between multitalk instances or bbraun’s `kwai` server

[![Build Status](https://github.com/sfiera/multitalk/actions/workflows/ci.yaml/badge.svg)](https://github.com/sfiera/multitalk/actions/workflows/ci.yaml) [![Go Reference](https://pkg.go.dev/badge/github.com/sfiera/multitalk/pkg.svg)](https://pkg.go.dev/github.com/sfiera/multitalk/pkg)

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
