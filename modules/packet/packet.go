package packet

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketInfo stores detailed information about a captured packet
type PacketInfo struct {
	Timestamp   time.Time
	SourceIP    string
	DestIP      string
	SourcePort  uint16
	DestPort    uint16
	Protocol    string
	Length      int
	TCPFlags    string // For TCP packets only
	SeqNumber   uint32 // For TCP packets only
	AckNumber   uint32 // For TCP packets only
	WindowSize  uint16 // For TCP packets only
	UDPLength   uint16 // For UDP packets only
	PayloadSize int
}

// map
// 1 if in map 0 if not
var bad map[string]int = make(map[string]int)

func MarkBad(ip string) {
    bad[ip] = 1
}

func isBad(ip string) bool {
    return bad[ip] == 1
}

func HandlePacket(packet gopacket.Packet) error {

	// Get IP layer info
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv4)

	// Create base packet info
	info := PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		SourceIP:  ip.SrcIP.String(),
		DestIP:    ip.DstIP.String(),
		Length:    len(packet.Data()),
	}

	// Handle TCP packets
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		return handleTCP(&info, tcpLayer.(*layers.TCP), packet)
	}

	// Handle UDP packets
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		return handleUDP(&info, udpLayer.(*layers.UDP), packet)
	}

	return nil
}


