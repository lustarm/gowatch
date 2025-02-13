package packet

import (
    "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func handleTCP(info *PacketInfo, tcp *layers.TCP, packet gopacket.Packet) error {
    // Fill in TCP specific info
    info.Protocol = "TCP"
    info.SourcePort = uint16(tcp.SrcPort)
    info.DestPort = uint16(tcp.DstPort)
    info.SeqNumber = tcp.Seq
    info.AckNumber = tcp.Ack
    info.WindowSize = tcp.Window

    // Build TCP flags string
    flags := ""
    if tcp.SYN {
        flags += "SYN "
    }
    if tcp.ACK {
        flags += "ACK "
    }
    if tcp.FIN {
        flags += "FIN "
    }
    if tcp.RST {
        flags += "RST "
    }
    if tcp.PSH {
        flags += "PSH "
    }
    if tcp.URG {
        flags += "URG "
    }
    info.TCPFlags = flags

    // Get payload size
    if app := packet.ApplicationLayer(); app != nil {
        info.PayloadSize = len(app.Payload())
    }

    // Check for suspicious TCP behavior
    checkSuspiciousTCP(info, tcp)

    return nil
}

func handleUDP(info *PacketInfo, udp *layers.UDP, packet gopacket.Packet) error {
    // Fill in UDP specific info
    info.Protocol = "UDP"
    info.SourcePort = uint16(udp.SrcPort)
    info.DestPort = uint16(udp.DstPort)
    info.UDPLength = uint16(udp.Length)

    // Get payload size
    if app := packet.ApplicationLayer(); app != nil {
        info.PayloadSize = len(app.Payload())
    }

    // Check for suspicious UDP behavior
    checkSuspiciousUDP(info)

    return nil
}
