package packet

import (
	"log"

	"github.com/google/gopacket/layers"
)

func checkSuspiciousTCP(info *PacketInfo, tcp *layers.TCP) {
    // Check for NULL scan
    if !tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST && !tcp.PSH && !tcp.URG {
        MarkBad(info.SourceIP)
    }

    // Check for common malicious ports
    suspiciousPorts := map[uint16]bool{
        22: true,    // SSH
        23: true,    // Telnet
        445: true,   // SMB
        3389: true,  // RDP
        4444: true,  // Metasploit
        5900: true,  // VNC
    }

    if suspiciousPorts[info.DestPort] {
        // Increment suspicious activity counter for this IP
    }

    // Check for potential port scanning
    if tcp.SYN && !tcp.ACK {
        // Could add port scan detection logic here
        // For example, tracking number of different ports accessed by same IP
    }

    if isBad(info.SourceIP) {
        // Additional logging or alerting could be added here
        log.Println("IMPORTANT! suspicious activity from IP: ", info.DestIP)
    }
}

// Helper function to check if a port is in a typical range
func isCommonPort(port uint16) bool {
    return port <= 1024 || (port >= 1024 && port <= 49151)
}

func checkSuspiciousUDP(info *PacketInfo) {
    // Check for common UDP-based attacks
    suspiciousUDPPorts := map[uint16]bool{
        53: true,    // DNS
        123: true,   // NTP (potential amplification attacks)
        161: true,   // SNMP
        1900: true,  // SSDP
    }

    if suspiciousUDPPorts[info.DestPort] {
        // Check for potential UDP-based attacks
        if info.PayloadSize > 512 { // Arbitrary threshold
            MarkBad(info.SourceIP)
        }
    }

    // Check for UDP flood
    if info.PayloadSize == 0 || info.PayloadSize > 1470 { // Max UDP payload size
        MarkBad(info.SourceIP)
    }
}
