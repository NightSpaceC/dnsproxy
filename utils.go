package main

import (
	"net"
	"net/netip"
	"strconv"
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