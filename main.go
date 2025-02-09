package main;

import (
    "fmt"
    "github.com/google/gopacket/pcap"
    // "github.com/google/gopacket"
)

func main() {
    devices, err := pcap.FindAllDevs();
    if err != nil {
        fmt.Println("Failed to find devices: ",  err)
        return
    }

    /*
    for _, device := range devices {
        // ! handle each interface
        err = handlePacket(device)
        if err != nil {
            fmt.Println("Failed to handle device " + device.Name + "correctly")
        }
    }
    */

    // ! Handle first device
    handleDevice(devices[0])
}

func handleDevice(device pcap.Interface) error {
    // data, metadata, err := gopacket.NewPacketSource()
    fmt.Println("Handling device " + device.Name)
    return nil
}
