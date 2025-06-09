package speaker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/teapotovh/dummylb/internal/ippool"
	ctrl "sigs.k8s.io/controller-runtime"
)

var arpspkrLog = ctrl.Log.WithName("arpspkr")

type ARPSpeaker struct {
	iface string
	trace bool

	handle  *afpacket.TPacket
	psource *gopacket.PacketSource
	packets chan *layers.ARP
	mac     net.HardwareAddr

	updates chan map[netip.Addr]ippool.Unit
}

func NewARPSpeaker(iface string, trace bool) *ARPSpeaker {
	return &ARPSpeaker{
		iface: iface,
		trace: trace,
	}
}

func (a *ARPSpeaker) Start(ctx context.Context) error {
	iface, err := net.InterfaceByName(a.iface)
	if err != nil {
		return fmt.Errorf("error while reading MAC address form ARP interface: %w", err)
	}
	a.mac = iface.HardwareAddr

	a.handle, err = afpacket.NewTPacket(afpacket.OptInterface(a.iface))
	if err != nil {
		return fmt.Errorf("error while sniffing for ARP pakcets: %w", err)
	}
	a.psource = gopacket.NewPacketSource(a.handle, layers.LinkTypeEthernet)

	go a.pcap(ctx)
	go a.speaker(ctx)

	<-ctx.Done()
	return nil
}

func filterIPv4s(ips map[netip.Addr]ippool.Unit) map[netip.Addr]ippool.Unit {
	result := map[netip.Addr]ippool.Unit{}
	for ip, _ := range ips {
		if ip.Is4() {
			result[ip] = ippool.Unit{}
		}
	}
	return result
}

type pkt struct {
	packet gopacket.Packet
	layer  gopacket.Layer
}

func (a *ARPSpeaker) speaker(ctx context.Context) {
	arpspkrLog.Info("starting ARP speaker", "interface", a.iface)
	a.updates = ippool.Default.Subscribe()

	ips := map[netip.Addr]ippool.Unit{}
	buf := gopacket.NewSerializeBuffer()
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		case update := <-a.updates:
			ips = filterIPv4s(update)
			arpspkrLog.Info("got ip configuration update", "update", ips)
		case packet := <-a.packets:
			srcIP := netip.AddrFrom4([net.IPv4len]byte(packet.SourceProtAddress))
			dstIP := netip.AddrFrom4([net.IPv4len]byte(packet.DstProtAddress))

			if _, registered := ips[dstIP]; registered && packet.Operation == layers.ARPRequest {
				if a.trace {
					arpspkrLog.Info("got ARP request",
						"dst.ip", dstIP, "dst.mac", a.mac,
						"src.ip", srcIP, "src.mac", packet.DstHwAddress,
					)
				}

				reply := &layers.ARP{
					AddrType:          layers.LinkTypeEthernet,
					Protocol:          layers.EthernetTypeIPv4,
					HwAddressSize:     6,
					ProtAddressSize:   net.IPv4len,
					Operation:         layers.ARPReply,
					SourceHwAddress:   a.mac,
					SourceProtAddress: dstIP.AsSlice(),
					DstHwAddress:      packet.SourceHwAddress,
					DstProtAddress:    packet.SourceProtAddress,
				}

				eth := &layers.Ethernet{
					SrcMAC:       a.mac,
					DstMAC:       packet.SourceHwAddress,
					EthernetType: layers.EthernetTypeARP,
				}

				if err := buf.Clear(); err != nil {
					arpspkrLog.Error(err, "error while clearing packet buffer")
					continue
				}
				if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, reply); err != nil {
					arpspkrLog.Error(err, "error while serializing ARP reply")
					continue
				}
				if err := a.handle.WritePacketData(buf.Bytes()); err != nil {
					arpspkrLog.Error(err, "error while writing ARP reply on the wire")
					continue
				}

				if a.trace {
					arpspkrLog.Info("sent ARP reply", "packet", reply)
				}
			}
			break
		}
	}

	arpspkrLog.Info("stopped ARP speaker")
	close(a.updates)
}

func (a *ARPSpeaker) pcap(ctx context.Context) {
	arpspkrLog.Info("starting ARP sniffer")
	a.packets = make(chan *layers.ARP)

	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		default:
		}

		packet, err := a.psource.NextPacket()
		if err == afpacket.ErrTimeout {
			continue
		} else if err == io.EOF {
			running = false
			continue
		} else if err != nil {
			arpspkrLog.Error(err, "error while reading ARP packet")
			continue
		}

		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			a.packets <- arpLayer.(*layers.ARP)
		}
	}

	close(a.packets)
	arpspkrLog.Info("stopped ARP sniffer")
}
