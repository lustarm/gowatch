package packet

import (
    "fmt"
    "github.com/google/gopacket"
    // "github.com/google/gopacket/pcap"
)

func HandlePacket(packet gopacket.Packet) error {
    fmt.Println("Handling packet: ", packet.Metadata())

    return nil
}
