// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcapdump binary implements a tcpdump-like command line tool with gopacket
// using pcap as a backend data collection mechanism.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")
var decoder = flag.String("decoder", "Ethernet", "Name of the decoder to use")
var filter = flag.String("filter", "(tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01)", "Set the filter but default is set for TLS handshakes")
var dump = flag.Bool("X", false, "If true, dump very verbose info on each packet")

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		// This is a little complicated because we want to allow all possible options
		// for creating the packet capture handle... instead of all this you can
		// just call pcap.OpenLive if you want a simple handle.
		inactive, err := pcap.NewInactiveHandle(*iface)
		if err != nil {
			log.Fatalf("could not create: %v", err)
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(*snaplen); err != nil {
			log.Fatalf("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(*promisc); err != nil {
			log.Fatalf("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			log.Fatalf("could not set timeout: %v", err)
		}
		if *tstype != "" {
			if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			} else if err := inactive.SetTimestampSource(t); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			}
		}
		if handle, err = inactive.Activate(); err != nil {
			log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
	}
	if *filter != "" {
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", *filter)
		if err = handle.SetBPFFilter(*filter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}
	Run(handle)
}

func Run(src gopacket.PacketDataSource) {
	if !flag.Parsed() {
		log.Fatalln("Run called without flags.Parse() being called")
	}
	var dec gopacket.Decoder
	var ok bool
	if dec, ok = gopacket.DecodersByLayerName[*decoder]; !ok {
		log.Fatalln("No decoder named", *decoder)
	}
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true
	fmt.Fprintln(os.Stderr, "Starting to read packets")
	count := 0
	bytes := int64(0)
	errors := 0
	truncated := 0
	layertypes := map[gopacket.LayerType]int{}

	for packet := range source.Packets() {
		count++
		bytes += int64(len(packet.Data()))

		if *dump {
			fmt.Println(packet.Dump())
		}

		for _, layer := range packet.Layers() {
			layertypes[layer.LayerType()]++
		}
		if packet.Metadata().Truncated {
			truncated++
		}
		if errLayer := packet.ErrorLayer(); errLayer != nil {
			errors++
			fmt.Println("Error:", errLayer.Error())
			fmt.Println("--- Packet ---")
			fmt.Println(packet.Dump())
		}
		go readPacket(packet)
	}
}

func readPacket(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			log.Println("Could not decode TCP layer")
			return
		}
		if tcp.SYN {
			// Connection setup
		} else if tcp.FIN {
			// Connection teardown
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
			// Acknowledgement packet
		} else if tcp.RST {
			// Unexpected packet
		} else {
			// data packet
			readData(packet)
		}
	}
}

func readData(packet gopacket.Packet) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		t, _ := tcpLayer.(*layers.TCP)

		var hello = tlsx.ClientHello{}

		err := hello.Unmarshall(t.LayerPayload())

		switch err {
		case nil:
		case tlsx.ErrHandshakeWrongType:
			return
		default:
			log.Println("Error reading Client Hello:", err)
			log.Println("Raw Client Hello:", t.LayerPayload())
			return
		}
		log.Printf("Client hello from port %s to %s", t.SrcPort, t.DstPort)
		calcJA3(hello)
	} else {
		log.Println("Client Hello Reader could not decode TCP layer")
		return
	}
}

func calcJA3(hello tlsx.ClientHello) {
	fmt.Println(hello)
	fmt.Printf("Version: %d\n", hello.Version)
	fmt.Printf("Extensions: ")
	for e := range hello.Extensions {
		fmt.Printf("%d ", e)
	}
	fmt.Printf("\nCiphers: ")
	for e := range hello.CipherSuites {
		fmt.Printf("%d ", e)
	}
	fmt.Printf("\n")
}
