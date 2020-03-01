# Introduction

MultiTalk is a repeater for different transports for AppleTalk:
* EtherTalk, spoken by Classic MacOS or netatalk2 machines over Ethernet
* LocalTalk-over-UDP (LTOE) multicast, spoken by recent versions of minivmac
* TCP, spoken by the `kwai` component of bbraun’s abridge

# Usage

Convert between EtherTalk and LTOE on the ethernet port:

    sudo multitalk --ethertalk eth0 --multicast eth0

The same, except printing all packets for debugging:

    sudo multitalk -e eth0 -m eth0 --debug

# Credits

See [AUTHORS](AUTHORS)

Original abridge code by Rob Braun <bbraun@synack.net>
Conversion to MultiTalk by Chris Pickel [@sfiera](https://github.com/sfiera)
LTOE specification by Rob Mitchelmore [@cheesestraws](https://github.com/cheesestraws)
