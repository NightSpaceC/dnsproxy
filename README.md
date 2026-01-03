# dnsproxy
This is a DNS proxy to let you get correct response when GFW is polluting the network.

A feature of the pollution packets from GFW is that they don't support EDNS and have no additional field.

So we can distinguish and throw the packet without EDNS.

It also cause a limit, which is that your upstream server must support EDNS.

When you are using a client which does not support EDNS, this proxy will send packet with EDNS automatically.