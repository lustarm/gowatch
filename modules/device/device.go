package device

import (
	"gowatch/modules/packet"
	"gowatch/modules/stats"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func HandleDevice(device pcap.Interface) error {
    log.Println("Handling device " + device.Name)
    log.Println("Watching for malicious packets")

    handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)

    if err != nil {
        return err
    }

    defer handle.Close()

    // ! packet source
    ps := gopacket.NewPacketSource(handle, handle.LinkType())

    for p := range ps.Packets() {
        stats.GlobalStats.TotalPackets++

        err = packet.HandlePacket(p)

        if err != nil {
            return err
        }
    }

    return nil
}
