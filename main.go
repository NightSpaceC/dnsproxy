package main

import (
	"flag"
	"log"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

func main() {
	listenEndpoint :=  flag.String("l", "127.0.0.1", "proxy listen address")
	upstreamEndpoint :=  flag.String("u", "8.8.8.8", "upstream server address")
	alwaysWithSubnet :=  flag.Bool("s", false, "always send subnet to upstream server")
	flag.Parse()

	upstreamAddrPort, err := parseAddrPortWithDefaultPort(*upstreamEndpoint, 53)
	if err != nil {
		panic(err) 
	}

	listenAddrPort, err := parseAddrPortWithDefaultPort(*listenEndpoint, 53)
	if err != nil {
		panic(err) 
	}

	log.Printf("listen at %v\n", listenAddrPort)
	dns.ListenAndServe(listenAddrPort.String(), "udp", dns.HandlerFunc(func(resWriter dns.ResponseWriter, msg *dns.Msg) {
		opt := findOPT(msg.Extra)
		if opt == nil {
			opt = &dns.OPT{
				Hdr: dns.RR_Header{
					Name: ".",
					Rrtype: dns.TypeOPT,
				},
			}
			opt.SetUDPSize(512)
			msg.Extra = append(msg.Extra, opt)
		}

		if *alwaysWithSubnet {
			subnet := findSUBNET(opt.Option)
			if subnet == nil {
				remoteAddrPort, err := netip.ParseAddrPort(resWriter.RemoteAddr().String())
				if err != nil {
					log.Println(err)
					return
				}
				subnet = &dns.EDNS0_SUBNET{
					Code: dns.EDNS0SUBNET,
					Family: 1,
					SourceNetmask: 32,
					Address: remoteAddrPort.Addr().AsSlice(),
				}
				if remoteAddrPort.Addr().Is6() {
					subnet.Family = 2
					subnet.SourceNetmask = 128
				}
				opt.Option = append(opt.Option, subnet)
			}
		}

		upstream, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(upstreamAddrPort))
		if err != nil {
			log.Println(err)
			return
		}
		defer upstream.Close()

		msg_data, err := msg.Pack()
		if err != nil {
			log.Println(err)
			return
		}

		_, err = upstream.Write(msg_data)
		if err != nil {
			log.Println(err)
			return
		}
		log.Printf("send to upstream: %v\n", len(msg_data))

		buffer := make([]byte, 2048)
		for true {
			size, err := upstream.Read(buffer)
			if err != nil {
				log.Println(err)
				return
			}

			res := &dns.Msg{}
			err = res.Unpack(buffer[:size])
			if err != nil {
				log.Println(err)
				continue
			}

			if findOPT(res.Extra) == nil {
				continue
			}
			err = resWriter.WriteMsg(res)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Printf("receive from upstream: %v\n", size)
			break
		}
	}))
}