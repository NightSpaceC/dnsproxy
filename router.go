package main

import (
	"context"
	"encoding/hex"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ChannelWithPort struct {
	port uint16
	packetChannel chan <- []byte
}

func packetRouter(ctx context.Context, packetSource chan gopacket.Packet, registerSocketChan <- chan ChannelWithPort, closeSocketChan <- chan uint16) {
	packetChannels := make(map[uint16]chan <- []byte)
	for {
		select {
		case packet := <- packetSource:
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

			channel <- udp.Payload

		case channelWithPort := <- registerSocketChan:
			if _, ok := packetChannels[channelWithPort.port]; ok {
				log.Printf("duplicated socket with port %v\n", channelWithPort.port)
				continue
			}

			packetChannels[channelWithPort.port] = channelWithPort.packetChannel

		case port := <- closeSocketChan:
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

func registerSocket(registerSocketChannel chan <- ChannelWithPort, closeSocketChannel chan <- uint16, port uint16) (<- chan []byte, func()) {
	packetChannel := make(chan []byte)
	registerSocketChannel <- ChannelWithPort{
		port,
		packetChannel,
	}
	return packetChannel, func() {
		closeSocketChannel <- port
	}
}