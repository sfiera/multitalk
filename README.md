# Introduction

MultiTalk is a repeater for different transports for [AppleTalk][appletalk]:
* EtherTalk, spoken by Classic MacOS or [netatalk2][netatalk] machines over Ethernet
* [LocalTalk-over-UDP][ltou] (LToU) multicast, spoken by [Mini vMac][minivmac] 37+
* TCP, spoken between multitalk instances or bbraun’s `kwai` server
* [TashTalk][tashtalk], spoken by TashTalk-programmed PICs over serial

[![Build Status](https://github.com/sfiera/multitalk/actions/workflows/ci.yaml/badge.svg)](https://github.com/sfiera/multitalk/actions/workflows/ci.yaml) [![Go Reference](https://pkg.go.dev/badge/github.com/sfiera/multitalk/pkg.svg)](https://pkg.go.dev/github.com/sfiera/multitalk/pkg)

# Usage

Install the latest version of MultiTalk:

    go install github.com/sfiera/multitalk/cmd/multitalk@latest

Convert between EtherTalk and LToU on the ethernet port:

    sudo multitalk --ethertalk eth0 --multicast eth0

The same, except printing all packets for debugging:

    sudo multitalk -e eth0 -m eth0 --debug

# Credits

See [AUTHORS](AUTHORS). Notable contributions:

* Original [abridge][abridge] code by Rob Braun <bbraun@synack.net>
* Conversion to MultiTalk by Chris Pickel [@sfiera][sfiera]
* [LToU specification][ltou] by Rob Mitchelmore [@cheesestraws][cheesestraws]
* [TashTalk][tashtalk] specification by [@lampmerchant][lampmerchant]

[abridge]: http://www.synack.net/~bbraun/abridge.html
[appletalk]: https://en.wikipedia.org/wiki/AppleTalk
[ltou]: https://windswept.home.blog/2019/12/10/localtalk-over-udp/
[minivmac]: https://www.gryphel.com/c/minivmac/
[netatalk]: https://github.com/Netatalk/Netatalk
[tashtalk]: https://github.com/lampmerchant/tashtalk/blob/main/documentation/protocol.md

[cheesestraws]: https://github.com/cheesestraws
[lampmerchant]: https://github.com/lampmerchant
[sfiera]: https://github.com/sfiera
