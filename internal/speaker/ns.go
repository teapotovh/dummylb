package speaker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/teapotovh/dummylb/internal/ippool"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	nsspkrLog    = ctrl.Log.WithName("nsspkr")
	multicastMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
)

type NSSpeaker struct {
	iface string
	trace bool

	handle  *afpacket.TPacket
	psource *gopacket.PacketSource
	packets chan pkt
	mac     net.HardwareAddr
	ll      *netip.Addr

	updates chan map[netip.Addr]ippool.Unit
}

func NewNSSpeaker(iface string, trace bool) *NSSpeaker {
	return &NSSpeaker{
		iface: iface,
		trace: trace,
	}
}

func fetchLL(iface *net.Interface) (*netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("error while reading NS interface IP addresses: %w", err)
	}

	// ll is the link-local IPv6
	var ll *netip.Addr = nil
	for _, addr := range addrs {
		ip, err := netip.ParsePrefix(addr.String())
		if err != nil {
			nsspkrLog.Error(err, "error while parsing IP associaeted with NS interface", "iface", iface, "addr", addr.String())
			continue
		}

		addr := ip.Addr()
		if addr.Is6() && addr.IsLinkLocalUnicast() {
			ll = &addr
			break
		}
	}

	return ll, nil
}

func (a *NSSpeaker) Start(ctx context.Context) error {
	iface, err := net.InterfaceByName(a.iface)
	if err != nil {
		return fmt.Errorf("error while getting NS interface: %w", err)
	}
	a.mac = iface.HardwareAddr

	a.ll, err = fetchLL(iface)
	if err != nil {
		return err
	}
	if a.ll == nil {
		return fmt.Errorf("could not find link-local IPv6 address on NS interface: %s", a.iface)
	}

	a.handle, err = afpacket.NewTPacket(afpacket.OptInterface(a.iface))
	if err != nil {
		return fmt.Errorf("error while sniffing for NS pakcets: %w", err)
	}
	a.psource = gopacket.NewPacketSource(a.handle, layers.LinkTypeEthernet)

	go a.pcap(ctx)
	go a.speaker(ctx)
	go a.advertiser(ctx)

	<-ctx.Done()
	return nil
}

func filterIPv6s(ips map[netip.Addr]ippool.Unit) map[netip.Addr]ippool.Unit {
	result := map[netip.Addr]ippool.Unit{}
	for ip, _ := range ips {
		if ip.Is6() {
			result[ip] = ippool.Unit{}
		}
	}
	return result
}

// TODO(lucat1): look into avoiding these conversions between netip.Addr and net.IP

func netToNetip(ip *net.IP) netip.Addr {
	a, _ := netip.ParseAddr(ip.String())
	return a
}

func netipToNet(ip *netip.Addr) net.IP {
	return net.ParseIP(ip.String())
}

func (a *NSSpeaker) speaker(ctx context.Context) {
	nsspkrLog.Info("starting NS speaker", "interface", a.iface)
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
			ips = filterIPv6s(update)
			nsspkrLog.Info("got ip configuration update", "update", ips)
		case pkt := <-a.packets:
			eth := pkt.packet.LinkLayer().(*layers.Ethernet)
			ip := pkt.packet.NetworkLayer().(*layers.IPv6)
			ns := pkt.layer.(*layers.ICMPv6NeighborSolicitation)
			dstIP := netToNetip(&ns.TargetAddress)

			if _, registered := ips[dstIP]; registered {
				if a.trace {
					arpspkrLog.Info("got NS request",
						"dst.ip", dstIP, "dst.ll", a.ll,
						"src.ip", ip.SrcIP,
					)
				}
				eth := &layers.Ethernet{
					SrcMAC:       a.mac,
					DstMAC:       eth.SrcMAC,
					EthernetType: layers.EthernetTypeIPv6,
				}
				ipv6 := &layers.IPv6{
					Version:    6,
					SrcIP:      netipToNet(a.ll).To16(),
					DstIP:      ip.SrcIP.To16(),
					NextHeader: layers.IPProtocolICMPv6,
					HopLimit:   255,
				}
				icmp := &layers.ICMPv6{
					TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
				}
				icmp.SetNetworkLayerForChecksum(ipv6)
				na := &layers.ICMPv6NeighborAdvertisement{
					Flags:         0x60,
					TargetAddress: netipToNet(&dstIP),
					Options: []layers.ICMPv6Option{{
						Type: layers.ICMPv6OptTargetAddress,
						Data: a.mac,
					}},
				}

				if err := buf.Clear(); err != nil {
					arpspkrLog.Error(err, "error while clearing packet buffer")
					continue
				}
				err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
					ComputeChecksums: true,
					FixLengths:       true,
				}, eth, ipv6, icmp, na)
				if err != nil {
					arpspkrLog.Error(err, "error while serializing NA reply")
					continue
				}
				if err := a.handle.WritePacketData(buf.Bytes()); err != nil {
					arpspkrLog.Error(err, "error while writing NA reply on the wire")
					continue
				}

				if a.trace {
					arpspkrLog.Info("sent NA reply", "packet", na)
				}
			}
			break
		default:
		}

	}

	nsspkrLog.Info("stopped NS speaker")
	close(a.updates)
}

func (a *NSSpeaker) unsolicited(ips map[netip.Addr]ippool.Unit) {
	allLL := netip.IPv6LinkLocalAllNodes()
	buf := gopacket.NewSerializeBuffer()

	for dstIP, _ := range ips {
		eth := &layers.Ethernet{
			SrcMAC:       a.mac,
			DstMAC:       multicastMAC,
			EthernetType: layers.EthernetTypeIPv6,
		}
		ipv6 := &layers.IPv6{
			Version:    6,
			SrcIP:      netipToNet(a.ll).To16(),
			DstIP:      netipToNet(&allLL),
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
		}
		icmp := &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
		}
		icmp.SetNetworkLayerForChecksum(ipv6)
		na := &layers.ICMPv6NeighborAdvertisement{
			Flags:         0x20,
			TargetAddress: netipToNet(&dstIP),
			Options: []layers.ICMPv6Option{
				{
					Type: layers.ICMPv6OptTargetAddress,
					Data: a.mac,
				},
			},
		}

		if err := buf.Clear(); err != nil {
			arpspkrLog.Error(err, "error while clearing packet buffer")
			continue
		}
		err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}, eth, ipv6, icmp, na)
		if err != nil {
			arpspkrLog.Error(err, "error while serializing NA reply")
			continue
		}
		if err := a.handle.WritePacketData(buf.Bytes()); err != nil {
			arpspkrLog.Error(err, "error while writing NA reply on the wire")
			continue
		}

		if a.trace {
			arpspkrLog.Info("sent unsolicited NA", "packet", na)
		}
	}
}

func (a *NSSpeaker) advertiser(ctx context.Context) {
	nsspkrLog.Info("starting NS unsolicited advertiser", "interface", a.iface)
	a.updates = ippool.Default.Subscribe()

	ips := map[netip.Addr]ippool.Unit{}
	running := true
	ticker := time.NewTicker(time.Minute / 2)
	for running {
		select {
		case <-ctx.Done():
			running = false
			break
		case update := <-a.updates:
			ips = filterIPv6s(update)
			arpspkrLog.Info("got ip configuration update", "update", ips)
			a.unsolicited(ips)
			break
		case <-ticker.C:
			a.unsolicited(ips)
			break
		default:
		}

	}

	nsspkrLog.Info("stopped NS unsolicited advertiser")
	close(a.updates)
}

func (a *NSSpeaker) pcap(ctx context.Context) {
	nsspkrLog.Info("starting NS sniffer")
	a.packets = make(chan pkt)

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
			nsspkrLog.Error(err, "error while reading NS packet")
			time.Sleep(time.Second)
			continue
		}

		if nsLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation); nsLayer != nil {
			a.packets <- pkt{packet: packet, layer: nsLayer}
		}
	}

	close(a.packets)
	nsspkrLog.Info("stopped NS sniffer")
}
