package main

import (
	"context"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type channelWithPort struct {
	port uint16
	packetChannel chan <- []byte
}

type packetRouter struct {
	registerSocketChan chan channelWithPort
	closeSocketChan chan uint16
}

func newRouter() *packetRouter {
	return &packetRouter{
		registerSocketChan: make(chan channelWithPort),
		closeSocketChan: make(chan uint16),
	}
}

func (r *packetRouter) route(ctx context.Context, packetSource chan gopacket.Packet) {
	packetChannels := make(map[uint16]chan <- []byte)
	for {
		select {
		case packet := <- packetSource:
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				log.Printf("received a packet without udp layer: %v\n", len(packet.Data()))
				continue
			}

			udp := udpLayer.(*layers.UDP)

			channel, ok := packetChannels[uint16(udp.DstPort)]
			if !ok {
				continue
			}

			channel <- udp.Payload

		case channelWithPort := <- r.registerSocketChan:
			if _, ok := packetChannels[channelWithPort.port]; ok {
				log.Printf("duplicated socket with port %v\n", channelWithPort.port)
				continue
			}

			packetChannels[channelWithPort.port] = channelWithPort.packetChannel

		case port := <- r.closeSocketChan:
			if _, ok := packetChannels[port]; !ok {
				log.Printf("can not found socket with port %v\n", port)
				continue
			}

			delete(packetChannels, port)

		case <- ctx.Done():
			return
		}
	}
}

func (r *packetRouter) register(port uint16) (<- chan []byte, func()) {
	packetChannel := make(chan []byte)
	r.registerSocketChan <- channelWithPort{
		port,
		packetChannel,
	}
	return packetChannel, func() {
		r.closeSocketChan <- port
	}
}