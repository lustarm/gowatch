package main

import (
	"gowatch/modules/api"
	"gowatch/modules/device"
	"gowatch/modules/load"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
    // ! start api
    go api.StartAPI()

    // ! load from bad-ips
    err := load.Load()
    if err != nil {
        log.Fatalln("Failed to load IPs: ", err)
        return
    }

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

