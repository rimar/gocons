package main

import (
	"fmt"
	"flag"
	"log"
	"time"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	ifPtr := flag.String("if", "all", "interface name")
	timePtr := flag.Int("time", -1, "how long (sec) to run")

	flag.Parse()

	fmt.Println("interface:", *ifPtr)
	fmt.Println("time:", *timePtr)
	// fmt.Println("tail:", flag.Args())
	// fmt.Println("time:", time.Second)
	// log.Println("go gocons")

	list_ifs()
	if *ifPtr == "all" {
		fmt.Println("please supply the interface name using -if ifname flag")
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
	}
	return device
}

func list_ifs() map[string]string {
	res := map[string]string{}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, dev := range devices {
		for _, ifc := range dev.Addresses {
			ip := net.IP.To4(ifc.IP)
			if ip != nil && !net.IP.IsLoopback(ifc.IP) {
				res[ip.String()] = dev.Name
				fmt.Println(dev.Name, ip)
			}
		}
	}
	return res
}
