//go:build linux

package actuate

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"golang.org/x/net/ipv4"
)

// StartColdProbeResponder listens on UDP :port (all interfaces) and echoes
// back any datagram whose payload exactly matches the cold-prober's probe
// payload, so peer pathprofiler instances probing this host get a real UDP
// reply instead of depending on the destination's (often rate-limited) ICMP
// port-unreachable generation -- see ProbeLegBurst's doc comment.
//
// Only the fixed probe payload is echoed, not arbitrary traffic, so this
// isn't a generic open UDP echo/reflection service -- reflecting requires
// already knowing the exact probe payload, and the echo is 1:1 size (no
// amplification). Still: only enable on trusted underlay/transit meshes, not
// networks reachable by untrusted parties.
//
// Caller should Close() the returned conn on shutdown; the read loop exits
// once the conn is closed.
//
// When verbose is true, every received datagram is logged (source, size,
// and whether it matched the expected probe payload) and echo failures are
// logged instead of being silently swallowed -- useful for diagnosing "no
// replies arriving" reports where it's unclear whether the process is even
// receiving traffic.
//
// Replies are sourced from the exact local address the probe was addressed
// to (via IP_PKTINFO, ipv4.ControlMessage.Src), not whatever address the
// kernel would pick by routing to the sender. On a multihomed router those
// differ: a probe sent to a loopback/router-id address that arrives on a
// physical underlay interface would otherwise get echoed back with that
// interface's own address as source instead of the loopback's. ProbeLegBurst
// connect()s its client socket to the exact address it probed (see its
// "traceroute idiom" doc comment), so a reply from any other local address
// is silently dropped by the kernel's connected-UDP peer filtering -- the
// probe looks "lost" even though the responder answered.
func StartColdProbeResponder(port int, verbose bool) (*ipv4.PacketConn, error) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, fmt.Errorf("listen udp :%d: %w", port, err)
	}

	pc := ipv4.NewPacketConn(udpConn)
	if err := pc.SetControlMessage(ipv4.FlagDst, true); err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("enable IP_PKTINFO on :%d: %w", port, err)
	}

	go func() {
		want := []byte(probePayload)
		buf := make([]byte, 512) // matches ProbeLegBurst's recv buffer size
		for {
			n, cm, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if verbose {
					log.Printf("cold-probe responder: read error, exiting: %v", err)
				}
				return // conn closed -> exit goroutine
			}
			if n != len(want) || !bytes.Equal(buf[:n], want) {
				if verbose {
					log.Printf("cold-probe responder: ignored %d-byte datagram from %s (payload mismatch, want %q got %q)",
						n, addr, want, buf[:n])
				}
				continue
			}
			reply := &ipv4.ControlMessage{Src: cm.Dst}
			if _, err := pc.WriteTo(buf[:n], reply, addr); err != nil {
				if verbose {
					log.Printf("cold-probe responder: echo to %s failed: %v", addr, err)
				}
				continue
			}
			if verbose {
				log.Printf("cold-probe responder: echoed probe to %s (src %s)", addr, cm.Dst)
			}
		}
	}()

	return pc, nil
}
