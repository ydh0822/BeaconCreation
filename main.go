package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	BEC()
}

const (
	defaultSnapLen = 262144
)

func BEC() {
	fmt.Println("__BEC Start__")

	var name string
	fmt.Printf("Input Wireless interface Name : ")
	fmt.Scanln(&name)

	handle, err := pcap.OpenLive(name, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var radiotap layers.RadioTap      // radiotap 설정
	var beacon layers.Dot11MgmtBeacon // 비콘 선언
	beacon.Timestamp = uint64(time.Now().Unix())
	beacon.Interval = 100

	//radiotap 필드 설정
	radiotap.Present = layers.RadioTapPresentTSFT | layers.RadioTapPresentFlags | layers.RadioTapPresentRate
	radiotap.TSFT = uint64(time.Now().UnixNano() / 1000)
	radiotap.Rate = 2

	packet := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	for {
		err := gopacket.SerializeLayers(packet, opts, &beacon)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("beacon: %v\n", beacon)
		fmt.Printf("beacon.Contents: %v\n", beacon.Contents)
		fmt.Printf("beacon.Dot11Mgmt: %v\n", beacon.Dot11Mgmt)
		handle.WritePacketData(packet.Bytes())
		time.Sleep(time.Millisecond * 50)
	}
}
