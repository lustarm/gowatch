package packet

import (
	"time"
    "net"

	"gowatch/modules/stats"

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
var BadCount int

func MarkBad(ip string) {
    // Parse the IP address
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return // Invalid IP address
    }

    // Check if it's a local IP address
    if isLocalIP(parsedIP) {
        return // Don't mark local IPs as bad
    }

    stats.GlobalStats.SuspiciousIPs++
    bad[ip] = 1
}


// isLocalIP checks if an IP address is local
func isLocalIP(ip net.IP) bool {
    // Check for loopback addresses (127.0.0.0/8)
    if ip.IsLoopback() {
        return true
    }

    // Check for private network ranges
    privateNetworks := []struct {
        network string
        mask    string
    }{
        {"10.0.0.0", "255.0.0.0"},       // 10.0.0.0/8
        {"172.16.0.0", "255.240.0.0"},   // 172.16.0.0/12
        {"192.168.0.0", "255.255.0.0"},  // 192.168.0.0/16
        {"169.254.0.0", "255.255.0.0"},  // Link-local (169.254.0.0/16)
    }

    for _, network := range privateNetworks {
        ip4 := ip.To4()
        if ip4 == nil {
            continue // Skip if not IPv4
        }

        networkIP := net.ParseIP(network.network)
        mask := net.IPMask(net.ParseIP(network.mask).To4())

        if networkIP.Mask(mask).Equal(ip4.Mask(mask)) {
            return true
        }
    }

    return false
}


func isBad(ip string) bool {
    // Parse the IP address
    parsedIP := net.ParseIP(ip)
    if parsedIP == nil {
        return false
    }

    if isLocalIP(parsedIP) {
        return false
    }

    if bad[ip] != 1{
        return false
    }
    BadCount++
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


