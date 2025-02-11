package main;

import (
    "log"
    "gowatch/modules/device"
    "gowatch/modules/api"
    "github.com/google/gopacket/pcap"
)

func main() {
    // ! start api
    go api.StartAPI()

    devices, err := pcap.FindAllDevs();
    if err != nil {
        log.Println("Failed to find devices: ",  err)
        return
    }

    // ! Handle first device
    err = device.HandleDevice(devices[0])
    if err != nil {
        log.Println("Failed to handle device correctly: ", err)
        return
    }
}

