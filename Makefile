NAME=BEC

all: deps build

deps:
	go get github.com/google/gopacket

build:
	go build -o ${NAME} main.go
	sudo apt-get install libpcap-dev

clean:
	go clean
	rm ${NAME}