# dnsproxy
**The master branch was deprecated, please use [nopcap](https://github.com/NightSpaceC/dnsproxy/tree/nopcap)**

This is a DNS proxy to let you get correct response when GFW is polluting the network.

A feature of the pollution packets from GFW is that they don't support EDNS and have no additional field.

So we can use the filter rule `udp[18:2] != 0` to ignore them.

It also cause a limit, which is that your client and server must support EDNS.

This program use libpcap to get the full packets and filter packets, so maybe you should run it with a higher privilege.

If you want to use it on Windows, you should install [Npcap](https://npcap.com/) first.