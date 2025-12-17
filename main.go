package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/google/gopacket"
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

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	router := newRouter()
	go router.route(ctx, packetSource.Packets())

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
		log.Printf("receive request from %v: %v\n", clientAddrPort, len(data))

		go func() {
			upstream, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(upstreamAddrPort))
			if err != nil {
				log.Println(err)
				return
			}
			defer upstream.Close()
			localAddrPort, _ := netip.ParseAddrPort(upstream.LocalAddr().String())

			upstreamChannel, closeUpstreamChannel := router.register(localAddrPort.Port())
			defer closeUpstreamChannel()

			_, err = upstream.Write(data)
			if err != nil {
				log.Println(err)
				return
			}
			log.Printf("send to upstream from %v: %v\n", localAddrPort.Port(), len(data))

			receiveTimeout, cancel := context.WithTimeout(ctx, 10 * time.Second)
			defer cancel()

			var data []byte
			select {
			case data = <- upstreamChannel:
				break
			
			case <- receiveTimeout.Done():
				log.Printf("timeout from %v\n", localAddrPort.Port())
				return
			}
			log.Printf("receive from upstream at %v: %v\n", localAddrPort.Port(), len(data))

			_, err = server.WriteToUDPAddrPort(data, clientAddrPort)
			if err != nil {
				log.Println(err)
				return
			}
			log.Printf("send response to %v: %v\n", clientAddrPort, len(data))
		}()
	}
}