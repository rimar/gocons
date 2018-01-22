package main

import (
	"fmt"
	"flag"
	"log"
	"time"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
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

	localIps := list_ifs()
	if *ifPtr == "all" {
		fmt.Println("please supply the interface name using -if ifname flag")
	} else {
		capture(*ifPtr, "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0", localIps)
	}
}


func capture(device string, filter string, localIps map[string]string) string {

	seen := map[string]bool{}

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
		// Get the IPv4 layer from this packet
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				dst := fmt.Sprintf("%s:%d", ip.DstIP, tcp.DstPort)
				if !seen[dst] {
					seen[dst] = true
					fmt.Println(dst)
				}			  	
			}
		}
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
