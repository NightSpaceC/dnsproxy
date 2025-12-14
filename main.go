package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func printInterfaces() error {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	for _, each := range interfaces {
		_, err := fmt.Println(each.Name, each.Description)
		if err != nil {
			return err
		}
	}
	return nil
}

func selectInterface(interfaceName string) (pcap.Interface, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, err
	}

	index := slices.IndexFunc(interfaces, func (iface pcap.Interface) bool {
		return iface.Name == interfaceName
	})
	if index == -1 {
		return pcap.Interface{}, fmt.Errorf("can't find %s", interfaceName)
	}

	return interfaces[index], nil
}

type ChannelWithPort struct {
	port uint16
	packetChannel chan <- []byte
}

func forwardPackets(packetChannel chan gopacket.Packet, registerSocket <- chan ChannelWithPort, closeSocket <- chan uint16) {
	packetChannels := make(map[uint16]chan <- []byte)
	for {
		select {
		case packet := <- packetChannel:
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				log.Printf("received a packet without udp layer: %v\n", hex.EncodeToString(packet.Data()))
				continue
			}

			udp := udpLayer.(*layers.UDP)

			channel, ok := packetChannels[uint16(udp.DstPort)]
			if !ok {
				continue
			}

			data := make([]byte, len(udp.Payload))
			copy(data, udp.Payload)
			channel <- data

		case channelWithPort := <- registerSocket:
			if _, ok := packetChannels[channelWithPort.port]; ok {
				log.Printf("duplicated socket with port %v\n", channelWithPort.port)
				continue
			}

			packetChannels[channelWithPort.port] = channelWithPort.packetChannel

		case port := <- closeSocket:
			if _, ok := packetChannels[port]; !ok {
				log.Printf("can not found socket with port %v\n", port)
				continue
			}

			delete(packetChannels, port)
		}
	}
}

func main() {
	showInterfaces := flag.Bool("s", false, "To show all the usable network interfaces")
	interfaceName := flag.String("i", "eth0", "The network interface you want to sniff")
	listenEndpoint :=  flag.String("l", "127.0.0.1:53", "The address and port you want to listen")
	upstreamEndpoint :=  flag.String("u", "8.8.8.8", "The upstream server")
	flag.Parse()

	if *showInterfaces {
		err := printInterfaces()
		if err != nil {
			panic(err)
		}
		return
	}

	iface, err := selectInterface(*interfaceName)
	if err != nil {
		panic(err)
	}

	upstreamAddrPort, err := parseAddrPortWithDefaultPort(*upstreamEndpoint, 53)
	if err != nil {
		panic(err)
	}

	packetSource, closeHandle, err := createPacketSource(iface, upstreamAddrPort)
	if err != nil {
		panic(err)
	}
	defer closeHandle()

	packetChannel := packetSource.Packets()
	registerSocket := make(chan ChannelWithPort)
	closeSocket := make(chan uint16)

	go forwardPackets(packetChannel, registerSocket, closeSocket)

	listenAddrPort, err := parseAddrPortWithDefaultPort(*listenEndpoint, 53)
	if err != nil {
		panic(err)
	}

	server, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(listenAddrPort))
	if err != nil {
		panic(err)
	}
	defer server.Close()
	log.Printf("listen at %v\n", listenAddrPort)

	buffer := make([]byte, 65536)
	for {
		size, clientAddrPort, err := server.ReadFromUDPAddrPort(buffer)
		if err != nil {
			panic(err)
		}

		data := make([]byte, size)
		copy(data, buffer[0:size])
		log.Printf("receive request from %v: %v\n", clientAddrPort, hex.EncodeToString(data))

		go func() {
			upstream, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(upstreamAddrPort))
			if err != nil {
				log.Println(err)
				return
			}
			defer upstream.Close()
			localAddrPort, _ := netip.ParseAddrPort(upstream.LocalAddr().String())

			upstreamDownChannel := make(chan []byte)
			registerSocket <- ChannelWithPort{
				localAddrPort.Port(),
				upstreamDownChannel,
			}
			defer func() {
				closeSocket <- localAddrPort.Port()
			}()

			_, err = upstream.Write(data)
			if err != nil {
				log.Println(err)
				return
			}
			log.Printf("send to upstream from %v: %v\n", localAddrPort.Port(), hex.EncodeToString(data))

			data := <- upstreamDownChannel
			log.Printf("receive from upstream at %v: %v\n", localAddrPort.Port(), hex.EncodeToString(data))

			_, err = server.WriteToUDPAddrPort(data, clientAddrPort)
			if err != nil {
				log.Println(err)
				return
			}
			log.Printf("send response to %v: %v\n", clientAddrPort, hex.EncodeToString(data))
		}()
	}
}