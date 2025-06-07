package speaker

import (
	"context"
	"io"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/teapotovh/dummylb/internal/ippool"
	ctrl "sigs.k8s.io/controller-runtime"
)

var arpspkrLog = ctrl.Log.WithName("arpspkr")

type ARPSpeaker struct {
	iface   string
	psource *gopacket.PacketSource

	updates chan []netip.Addr
	packets chan gopacket.Packet
}

func NewARPSpeaker(iface string) *ARPSpeaker {
	handle, err := pcap.OpenLive(iface, 1600, true, time.Second*5)
	if err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil { // optional
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return &ARPSpeaker{
		iface:   iface,
		psource: packetSource,
		updates: ippool.Default.Subscribe(),
	}
}

func (a *ARPSpeaker) Start(ctx context.Context) error {
	arpspkrLog.Info("starting ARP speaker", "iface", a.iface)

	go a.pcap(ctx)

	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		case update := <-a.updates:
			arpspkrLog.Info("got ip configuration update", "update", update)
			break
		case packet := <-a.packets:
			arpspkrLog.Info("got packet", "packet", packet)
			break
		default:
		}

	}

	arpspkrLog.Info("stopped ARP speaker")
	close(a.updates)
	close(a.packets)
	return nil
}

func (a *ARPSpeaker) pcap(ctx context.Context) {
	arpspkrLog.Info("starting ARP sniffer")
	a.packets = make(chan gopacket.Packet)

	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		default:
		}

		packet, err := a.psource.NextPacket()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err == io.EOF {
			running = false
			continue
		} else if err != nil {
			arpspkrLog.Error(err, "error while reading ARP packet")
			continue
		}

		arpspkrLog.Info("before")
		a.packets <- packet
		arpspkrLog.Info("after")
	}

	close(a.packets)
	arpspkrLog.Info("stopped ARP sniffer")
}
