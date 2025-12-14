# dnsproxy
This is a DNS proxy to let you get correct response when GFW is polluting the network.

A feature of the pollution packet from GFW is that the DF segment in IP layer is always true.

So we can use the filter rule `ip[6] & 0x40 == 0` to ignore them.

This program use libpcap to get the full packets and filter packets, so maybe you should run it with a higher privilege.

If you want to use it on Windows, you should install [Npcap](https://npcap.com/) first.