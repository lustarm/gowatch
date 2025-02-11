package packet

import (
	"fmt"
	"log"
	"strings"
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

func markBad(ip string) {
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

func handleUDP(info *PacketInfo, udp *layers.UDP, _ gopacket.Packet) error {
    // ! just init everytime
    markBad("37.221.76.214")

	info.Protocol = "UDP"
	info.SourcePort = uint16(udp.SrcPort)
	info.DestPort = uint16(udp.DstPort)
	info.UDPLength = uint16(udp.Length)
	info.PayloadSize = len(udp.Payload)

    if !isBad(info.SourceIP) {
        return nil
    }

    log.Printf("Malicous UDP packet found")

	// Log interesting UDP information
	log.Printf("UDP Packet: %s:%d -> %s:%d, Length: %d bytes\n",
		info.SourceIP, info.SourcePort,
		info.DestIP, info.DestPort,
		info.Length)

    /*
	// Detect common UDP protocols based on port
	switch {
	case info.DestPort == 53 || info.SourcePort == 53:
		log.Println("DNS traffic detected")
		// You could add DNS packet parsing here
	case info.DestPort == 161 || info.SourcePort == 161:
		log.Println("SNMP traffic detected")
	case info.DestPort == 1900 || info.SourcePort == 1900:
		log.Println("SSDP (UPnP) traffic detected")
	case info.DestPort == 5353 || info.SourcePort == 5353:
		log.Println("mDNS traffic detected")
	}
    */

	return nil
}

func handleTCP(info *PacketInfo, tcp *layers.TCP, _ gopacket.Packet) error {
    // ! just init everytime
    markBad("37.221.76.214")

	info.Protocol = "TCP"
	info.SourcePort = uint16(tcp.SrcPort)
	info.DestPort = uint16(tcp.DstPort)
	info.SeqNumber = tcp.Seq
	info.AckNumber = tcp.Ack
	info.WindowSize = tcp.Window
	info.PayloadSize = len(tcp.Payload)

    if !isBad(info.SourceIP) {
        return nil
    }

    log.Println("Malicious TCP packet found")

	// Build TCP flags string
	flags := []string{}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	info.TCPFlags = fmt.Sprintf("[%s]", strings.Join(flags, ","))

	// Log interesting TCP information
	log.Printf("TCP Packet: %s:%d -> %s:%d, Flags: %s, Seq: %d, Ack: %d\n",
		info.SourceIP, info.SourcePort,
		info.DestIP, info.DestPort,
		info.TCPFlags, info.SeqNumber, info.AckNumber)

	// Detect common TCP protocols based on port
	switch {
	case info.DestPort == 80 || info.SourcePort == 80:
		log.Println("HTTP traffic detected")
		// You could add HTTP packet parsing here
	case info.DestPort == 443 || info.SourcePort == 443:
		log.Println("HTTPS traffic detected")
	case info.DestPort == 22 || info.SourcePort == 22:
		log.Println("SSH traffic detected")
	case info.DestPort == 21 || info.SourcePort == 21:
		log.Println("FTP traffic detected")
	}

	return nil
}

