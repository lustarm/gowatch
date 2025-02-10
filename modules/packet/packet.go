package packet

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	// "github.com/google/gopacket/pcap"
)

func HandlePacket(packet gopacket.Packet) error {

    // ! tcp packet
    if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
        fmt.Println("tcp packet intercepted: ", packet.Data())
        handleTCP(&packet)
    }

    // ! udp packet
    if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
        fmt.Println("udp packet intercepted: ", packet.Data())
        handleUDP(&packet)
    }

    return nil
}

// ! later

func handleUDP(p *gopacket.Packet) error {

    return nil
}

func handleTCP(p *gopacket.Packet) error {
    return nil
}
