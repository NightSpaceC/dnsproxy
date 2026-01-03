package main

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/miekg/dns"
)

func parseAddrPortWithDefaultPort(endpoint string, defaultPort uint16) (netip.AddrPort, error) {
	addressString, portString, err := net.SplitHostPort(endpoint)
	if err != nil {
		address, err := netip.ParseAddr(endpoint)
		if err != nil {
			return netip.AddrPort{}, err
		}

		return netip.AddrPortFrom(address, defaultPort), nil
	}
	address, err := netip.ParseAddr(addressString)
	if err != nil {
		return netip.AddrPort{}, err
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		return netip.AddrPort{}, err
	}

	return netip.AddrPortFrom(address, uint16(port)), nil
}

func findOPT(ar []dns.RR) (opt *dns.OPT) {
	for _, each := range ar {
		opt, _ = each.(*dns.OPT)
		if opt != nil {
			break
		}
	}
	return
}

func findSUBNET(options []dns.EDNS0) (subnet *dns.EDNS0_SUBNET) {
	for _, each := range options {
		subnet, _ = each.(*dns.EDNS0_SUBNET)
		if subnet != nil {
			break
		}
	}
	return
}