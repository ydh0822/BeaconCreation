package main

import (
	"fmt"
	"log"
	"os"
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

func DectoHex(byte_list []byte) {
	fmt.Println("%02x ", byte_list)
}

func BEC() {
	fmt.Println("__BEC Start__")

	var name string
	fmt.Printf("Input Wireless interface Name : ")
	fmt.Scanln(&name)

	handle, err := pcap.OpenLive(name, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
	defer handle.Close()

	Turnonmon(name) // turn on monitor mode

	basePacket := []byte{0, 0, 24, 0, 46, 64, 0, 160, 32, 8, 0, 0, 0, 2, 113, 9, 160, 0, 201, 0, 0, 0, 201, 0, 128, 0, 0, 0, 255, 255, 255, 255, 255, 255, 4, 212, 196, 81, 211, 104, 4, 212, 196, 81, 211, 104, 0, 186, 137, 113, 28, 97, 8, 0, 0, 0, 100, 0, 17, 4, 0, 15, 66, 111, 66, 95, 77, 101, 110, 116, 111, 114, 82, 49, 95, 50, 71, 1, 8, 130, 132, 139, 150, 36, 48, 72, 108, 3, 1, 3, 5, 4, 0, 3, 0, 0, 7, 6, 75, 82, 4, 1, 13, 20, 35, 2, 22, 0, 42, 1, 2, 50, 4, 12, 18, 24, 96, 48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 140, 0, 11, 5, 0, 0, 76, 0, 0, 66, 1, 0, 45, 26, 239, 17, 23, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 61, 22, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 74, 14, 20, 0, 10, 0, 44, 1, 200, 0, 20, 0, 5, 0, 25, 0, 127, 8, 5, 0, 8, 0, 0, 0, 0, 64, 191, 12, 177, 105, 131, 15, 170, 255, 0, 0, 170, 255, 0, 0, 192, 5, 0, 3, 0, 0, 0, 221, 53, 0, 80, 242, 4, 16, 74, 0, 1, 16, 16, 68, 0, 1, 2, 16, 71, 0, 16, 190, 108, 141, 199, 58, 29, 215, 47, 145, 82, 152, 22, 210, 117, 241, 78, 16, 60, 0, 1, 3, 16, 73, 0, 10, 0, 55, 42, 0, 1, 32, 5, 2, 7, 132, 221, 37, 248, 50, 228, 1, 1, 1, 2, 1, 0, 3, 20, 0, 72, 103, 13, 47, 214, 95, 190, 123, 213, 229, 247, 200, 195, 146, 51, 90, 237, 59, 136, 7, 4, 90, 237, 59, 136, 221, 30, 0, 144, 76, 4, 24, 191, 12, 177, 105, 131, 15, 170, 255, 0, 0, 170, 255, 0, 0, 192, 5, 0, 3, 0, 0, 0, 195, 2, 0, 2, 221, 9, 0, 16, 24, 2, 0, 0, 156, 0, 0, 221, 24, 0, 80, 242, 2, 1, 1, 132, 0, 3, 164, 0, 0, 39, 164, 0, 0, 66, 67, 94, 0, 98, 50, 47, 0, 221, 7, 80, 111, 154, 22, 1, 1, 0}
	DectoHex(basePacket)

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
		// fmt.Printf("beacon: %v\n", beacon)
		// fmt.Printf("beacon.Contents: %v\n", beacon.Contents)
		// fmt.Printf("beacon.Dot11Mgmt: %v\n", beacon.Dot11Mgmt)
		// fmt.Printf("beacon.LayerContents: %v\n", beacon.LayerContents())
		// beacon.LayerContents()

		handle.WritePacketData(packet.Bytes())
		time.Sleep(time.Millisecond * 50)
	}
}
