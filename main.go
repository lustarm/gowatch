package main;

import (
    "fmt"
    "gowatch/modules/device"
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
    err = device.HandleDevice(devices[0])
    if err != nil {
        fmt.Println("Failed to handle device correctly: ", err)
        return
    }
}

