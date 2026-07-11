//go:build linux

// pathprofiler-responder: standalone binary that answers cold-path probes
// from pathprofiler-daemon instances with real UDP echoes (see
// actuate.StartColdProbeResponder), so probing doesn't depend on the
// destination's (often rate-limited) ICMP port-unreachable generation. Does
// not load BPF, talk to FRR, or run any scoring/actuation -- it only echoes
// matching probes. No YAML config, no root/capabilities required.
package main

import (
	"flag"
	"log"

	"pathprofiler/internal/actuate"
)

func main() {
	port := flag.Int("port", 33434, "UDP port to listen on and echo cold-probe payloads from")
	verbose := flag.Bool("verbose", false, "log every received datagram (matched or not) and echo failures")
	flag.Parse()

	conn, err := actuate.StartColdProbeResponder(*port, *verbose)
	if err != nil {
		log.Fatalf("cold-probe responder: %v", err)
	}
	defer conn.Close()

	log.Printf("pathprofiler-responder: listening on UDP :%d (verbose=%v)", *port, *verbose)
	select {}
}
