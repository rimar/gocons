package main

import (
	"fmt"
	"flag"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

    ifPtr := flag.String("interface", "all", "interface name")
    timePtr := flag.Int("time", -1, "how long (sec) to run")

    flag.Parse()

    fmt.Println("interface:", *ifPtr)
    fmt.Println("time:", *timePtr)
    fmt.Println("tail:", flag.Args())
    fmt.Println("time:", time.Second)
    log.Println("go gocons")
    
    if *ifPtr == "all" {
		list_ifs()
    } else {
    	capture(*ifPtr, "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0")		
    }    
}


func capture(device string, filter string) string {

	// Open device
	handle, err := pcap.OpenLive(device, 100, false, time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Capturing: ", filter)

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
		//if capture to pcap file enable then file_cap(packet) etc
	}
	return device
}

func list_ifs() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < len(devices); i++ {
		dev := devices[i]
		fmt.Println(dev.Name)
	}
}