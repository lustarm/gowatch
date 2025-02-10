package device

import (
    "fmt"
    "gowatch/modules/packet"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket"
)

func HandleDevice(device pcap.Interface) error {
    fmt.Println("Handling device " + device.Name)

    handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)

    if err != nil {
        return err
    }

    defer handle.Close()

    // ! packet source
    ps := gopacket.NewPacketSource(handle, handle.LinkType())

    for p := range ps.Packets() {
        err = packet.HandlePacket(p)

        if err != nil {
            return err
        }
    }

    return nil
}
