package main

import (
	"gowatch/modules/api"
	"gowatch/modules/config"
	"gowatch/modules/device"
	"gowatch/modules/load"
	"log"
	"time"

	"github.com/google/gopacket/pcap"
)

func main() {
    // ! start api
    go api.Start()

    // ! load from bad-ips
    err := load.Load()
    if err != nil {
        log.Fatalln("Failed to load IPs: ", err)
        return
    }

    err = config.Load()
    if err != nil {
        log.Fatalln("Failed to load config: ", err)
        return
    }

    for {
        devices, err := pcap.FindAllDevs();
        if err != nil {
            log.Println("Failed to find devices: ",  err)
            return
        }

        for _, d := range devices {
            if d.Name == config.GlobalConfig.CaptureConfig.Interface {
                err = device.HandleDevice(d)

                if err != nil {
                    log.Println("Failed to handle device correctly: ", err)
                    return
                }
            }
        }

        log.Println("Failed to find device with name: ", config.GlobalConfig.CaptureConfig.Interface)
        log.Println("Please use the API to update your config")
        time.Sleep(time.Second * 5)
    }
}

