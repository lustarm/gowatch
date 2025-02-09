package device

import (
    "fmt"
    "github.com/google/gopacket/pcap"
)

func HandleDevice(device pcap.Interface) error {
    // data, metadata, err := gopacket.NewPacketSource()
    fmt.Println("Handling device " + device.Name)
    return nil
}
