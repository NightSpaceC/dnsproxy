package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
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

func createPacketSource(iface pcap.Interface, remoteAddrPort netip.AddrPort) (*gopacket.PacketSource, func(), error) {
	handle, err := pcap.OpenLive(iface.Name, 65535, false, pcap.BlockForever)
	if err != nil {
		return nil, nil, err
	}

	err = handle.SetBPFFilter(fmt.Sprintf("src host %v && udp && src port %v && ip[6] & 0x40 == 0", remoteAddrPort.Addr(), remoteAddrPort.Port()))
	if err != nil {
		return nil, nil, err
	}

	return gopacket.NewPacketSource(handle, handle.LinkType()), handle.Close, nil
}