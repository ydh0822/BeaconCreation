package main

import (
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	BEC()
}

func Turnonmon(name string) {
	ExcuteCMD("sudo", "ifconfig", name, "down")
	fmt.Println(name + " is down")
	ExcuteCMD("sudo", "iwconfig", name, "mode", "monitor")
	fmt.Println(name + " turn monitor mode")
	ExcuteCMD("sudo", "ifconfig", name, "up")
	fmt.Println(name + " is up \n")
}

func ExcuteCMD(script string, arg ...string) {
	cmd := exec.Command(script, arg...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		fmt.Println((err))
	} else {
		fmt.Println(string(output))
	}
}

const (
	defaultSnapLen = 262144
)

func BEC() {
	fmt.Println("__BEC Start__")

	var name string
	fmt.Printf("Input Wireless interface Name : ")
	fmt.Scanln(&name)

	Turnonmon(name) // turn on monitor mode

	handle, err := pcap.OpenLive(name, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var radiotap layers.RadioTap      // radiotap 설정
	var beacon layers.Dot11MgmtBeacon // 비콘 선언
	beacon.Timestamp = uint64(time.Now().Unix())
	beacon.Interval = 100
	beacon.Contents = []byte{0x03, 0x30, 0x20, 0x10}
	beacon.Dot11Mgmt.Payload = []byte{0xff, 0xdd, 0xaa, 0xbb}

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
		fmt.Printf("beacon.LayerContents: %v\n", beacon.LayerContents())
		handle.WritePacketData(packet.Bytes())
		time.Sleep(time.Millisecond * 50)
	}
}
