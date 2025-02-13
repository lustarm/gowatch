package stats

var GlobalStats Stats

// Thank you claud <3
type Stats struct {
	// Rate metrics
	PacketRateIn       int   // Incoming packets per second
	PacketRateOut      int   // Outgoing packets per second
	BytesRateIn  int64 // Incoming bytes per second
	BytesRateOut int64 // Outgoing bytes per second

	// Packet counts
	TotalPackets int64 // Total number of packets processed
	PacketsIn    int64 // Total incoming packets
	PacketsOut   int64 // Total outgoing packets

	// Byte counts
	TotalBytes int64 // Total bytes processed
	BytesIn    int64 // Total incoming bytes
	BytesOut   int64 // Total outgoing bytes

	// Security metrics
	MaliciousPackets   int // Detected malicious packets
	SuspiciousIPs      int // Number of suspicious IP addresses
	BlockedPackets     int // Number of blocked packets
	SecurityViolations int // Security policy violations
	SYNFloodCount      int //
	PortScanAttempts   int //

	// Error metrics
	Dropped        int // Dropped packets count
	Filtered       int // Filtered packets count
	Errors         int // General error count
	CRCErrors      int // Checksum error count
	BufferOverruns int // Buffer overrun count

	// Protocol metrics
	TCPPackets   int64 // TCP packets count
	UDPPackets   int64 // UDP packets count
	ICMPPackets  int64 // ICMP packets count
	OtherPackets int64 // Other protocol packets count

	// Performance metrics
	AverageLatency float64 // Average packet processing latency
	PeakLatency    float64 // Peak packet processing latency
	Jitter         float64 // Packet timing variation

	// Time tracking
	StartTime  int64 // Start time of statistics collection
	LastUpdate int64 // Last statistics update timestamp

	// Queue metrics
	QueueLength    int // Current queue length
	MaxQueueLength int // Maximum queue length reached

	// Connection tracking
	ActiveConns int   // Number of active connections
	TotalConns  int64 // Total connections handled
}
